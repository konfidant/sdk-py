import io
import json
import struct
from pathlib import Path

import pytest

from konfidant import knf
from konfidant.knf import KnfError

VECTORS = json.loads((Path(__file__).parent / "knf1-test-vectors.json").read_text(encoding="utf-8"))["vectors"]
KEY = bytes(range(32))
PREFIX = bytes.fromhex("a0a1a2a3a4a5a6")


def vector_ids(vectors):
    return [v["name"] for v in vectors]


def encrypt_vector(vector, source):
    return knf.encrypt(
        bytes.fromhex(vector["key_hex"]),
        source,
        kind=vector["kind"],
        name=vector["file_name"],
        mime=vector["mime"],
        chunk_size=vector["chunk_size"],
        _nonce_prefix=bytes.fromhex(vector["nonce_prefix_hex"]),
    )


# ---------------------------------------------------------------------------
# Test vectors
# ---------------------------------------------------------------------------


def test_vectors_are_present():
    assert len(VECTORS) >= 4


@pytest.mark.parametrize("vector", VECTORS, ids=vector_ids(VECTORS))
def test_vector_encrypt_bytes(vector):
    ciphertext = encrypt_vector(vector, bytes.fromhex(vector["plaintext_hex"]))
    assert ciphertext.hex() == vector["ciphertext_hex"]


@pytest.mark.parametrize("vector", VECTORS, ids=vector_ids(VECTORS))
def test_vector_encrypt_file_object(vector):
    ciphertext = encrypt_vector(vector, io.BytesIO(bytes.fromhex(vector["plaintext_hex"])))
    assert ciphertext.hex() == vector["ciphertext_hex"]


@pytest.mark.parametrize("vector", VECTORS, ids=vector_ids(VECTORS))
def test_vector_decrypt(vector):
    result = knf.decrypt(bytes.fromhex(vector["key_hex"]), bytes.fromhex(vector["ciphertext_hex"]))
    assert result.kind == vector["kind"]
    assert result.name == vector["file_name"]
    assert result.mime == vector["mime"]
    assert result.data.hex() == vector["plaintext_hex"]


@pytest.mark.parametrize("vector", VECTORS, ids=vector_ids(VECTORS))
def test_vector_decrypt_byte_by_byte(vector):
    decryptor = knf.Decryptor(bytes.fromhex(vector["key_hex"]))
    for byte in bytes.fromhex(vector["ciphertext_hex"]):
        decryptor.push(bytes([byte]))
    assert decryptor.finish().data.hex() == vector["plaintext_hex"]


@pytest.mark.parametrize("vector", VECTORS, ids=vector_ids(VECTORS))
def test_vector_key_encoding(vector):
    key = bytes.fromhex(vector["key_hex"])
    assert knf.encode_key(key) == vector["key_b64url"]
    assert knf.decode_key(vector["key_b64url"]) == key


@pytest.mark.parametrize("vector", VECTORS, ids=vector_ids(VECTORS))
def test_vector_ciphertext_size(vector):
    meta = knf.encode_metadata(vector["kind"], vector["file_name"], vector["mime"])
    size = knf.ciphertext_size(len(meta), len(vector["plaintext_hex"]) // 2, vector["chunk_size"])
    assert size == len(vector["ciphertext_hex"]) // 2


def test_vector_text_helpers():
    vector = next(v for v in VECTORS if v["name"] == "text-short")
    text = bytes.fromhex(vector["plaintext_hex"]).decode("utf-8")
    ciphertext = knf.encrypt_text(KEY, text, _nonce_prefix=PREFIX)
    assert ciphertext.hex() == vector["ciphertext_hex"]
    assert knf.decrypt(KEY, ciphertext).text == text


# ---------------------------------------------------------------------------
# Round trips
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("length", [0, 1, 4096 - 30, 4096 - 29, 4096 - 28, 4096 * 3, 4096 * 5 + 17, 100_000])
def test_round_trip_multi_chunk(length):
    content = bytes((i * 7) % 251 for i in range(length))
    ciphertext = knf.encrypt(KEY, content, kind="file", name="x.bin", mime="application/x", chunk_size=4096)
    meta_length = len(knf.encode_metadata("file", "x.bin", "application/x"))
    assert len(ciphertext) == knf.ciphertext_size(meta_length, length, 4096)
    result = knf.decrypt(KEY, ciphertext)
    assert (result.kind, result.name, result.mime, result.data) == ("file", "x.bin", "application/x", content)


def test_round_trip_streaming_in_odd_pieces():
    content = bytes(range(256)) * 200
    parts = list(knf.encrypt_stream(KEY, io.BytesIO(content), kind="file", name="a", chunk_size=4096))
    assert len(parts[0]) == knf.HEADER_SIZE
    assert all(len(p) == 4096 + knf.TAG_SIZE for p in parts[1:-1])
    ciphertext = b"".join(parts)
    decryptor = knf.Decryptor(KEY)
    for offset in range(0, len(ciphertext), 1000):
        decryptor.push(ciphertext[offset : offset + 1000])
    assert decryptor.finish().data == content


def test_round_trip_default_chunk_size_and_random_nonce():
    content = b"\x00" * (knf.DEFAULT_CHUNK_SIZE + 10)
    first = knf.encrypt(KEY, content, kind="file", name="big")
    second = knf.encrypt(KEY, content, kind="file", name="big")
    assert first != second  # fresh nonce prefix per call
    assert first[:4] == b"KNF1"
    assert struct.unpack(">I", first[4:8])[0] == knf.DEFAULT_CHUNK_SIZE
    assert knf.decrypt(KEY, first).data == content


def test_round_trip_unicode_text():
    text = "Grüße 🔐 — ünïcødé"
    ciphertext = knf.encrypt_text(KEY, text)
    result = knf.decrypt(KEY, ciphertext)
    assert (result.kind, result.name, result.mime, result.text) == ("text", "", "", text)


def test_decrypt_accepts_file_object():
    ciphertext = knf.encrypt(KEY, b"hello", kind="file", name="h.txt", chunk_size=4096)
    assert knf.decrypt(KEY, io.BytesIO(ciphertext)).data == b"hello"


def test_encrypt_stream_content_length_mismatch():
    stream = knf.encrypt_stream(KEY, io.BytesIO(b"abc"), kind="file", name="a", content_length=4)
    with pytest.raises(KnfError, match="expected 4"):
        b"".join(stream)


def test_encrypt_rejects_text_file_object():
    with pytest.raises(TypeError, match="binary mode"):
        knf.encrypt(KEY, io.StringIO("nope"), kind="file", name="a")  # type: ignore[arg-type]


def test_file_share_text_property_rejected():
    result = knf.decrypt(KEY, knf.encrypt(KEY, b"x", kind="file", name="a"))
    with pytest.raises(KnfError, match="not a text share"):
        _ = result.text


# ---------------------------------------------------------------------------
# Tampering, truncation, wrong key
# ---------------------------------------------------------------------------


@pytest.fixture
def multi_chunk_ciphertext():
    return knf.encrypt(KEY, bytes(10_000), kind="file", name="a.bin", chunk_size=4096, _nonce_prefix=PREFIX)


def test_wrong_key_fails(multi_chunk_ciphertext):
    with pytest.raises(KnfError, match="Decryption failed"):
        knf.decrypt(bytes(32), multi_chunk_ciphertext)


@pytest.mark.parametrize("position", [16, 100, 4096 + 16 + 5, -1])
def test_flipped_ciphertext_bit_fails(multi_chunk_ciphertext, position):
    tampered = bytearray(multi_chunk_ciphertext)
    tampered[position] ^= 0x01
    with pytest.raises(KnfError, match="Decryption failed"):
        knf.decrypt(KEY, bytes(tampered))


def test_modified_header_nonce_fails(multi_chunk_ciphertext):
    tampered = bytearray(multi_chunk_ciphertext)
    tampered[9] ^= 0x01  # nonce prefix, authenticated as AAD
    with pytest.raises(KnfError, match="Decryption failed"):
        knf.decrypt(KEY, bytes(tampered))


def test_truncated_at_chunk_boundary_fails(multi_chunk_ciphertext):
    # Dropping the final chunk leaves a valid-looking full chunk that was sealed as non-final.
    truncated = multi_chunk_ciphertext[: knf.HEADER_SIZE + 2 * (4096 + knf.TAG_SIZE)]
    with pytest.raises(KnfError, match="Decryption failed"):
        knf.decrypt(KEY, truncated)


def test_truncated_mid_chunk_fails(multi_chunk_ciphertext):
    with pytest.raises(KnfError, match="Decryption failed"):
        knf.decrypt(KEY, multi_chunk_ciphertext[:-5])


def test_truncated_to_header_fails(multi_chunk_ciphertext):
    with pytest.raises(KnfError, match="truncated"):
        knf.decrypt(KEY, multi_chunk_ciphertext[: knf.HEADER_SIZE + knf.TAG_SIZE])
    with pytest.raises(KnfError, match="truncated"):
        knf.decrypt(KEY, multi_chunk_ciphertext[:10])


def test_reordered_chunks_fail(multi_chunk_ciphertext):
    sealed = 4096 + knf.TAG_SIZE
    h = knf.HEADER_SIZE
    c0 = multi_chunk_ciphertext[h : h + sealed]
    c1 = multi_chunk_ciphertext[h + sealed : h + 2 * sealed]
    rest = multi_chunk_ciphertext[h + 2 * sealed :]
    with pytest.raises(KnfError, match="Decryption failed"):
        knf.decrypt(KEY, multi_chunk_ciphertext[:h] + c1 + c0 + rest)


def test_appended_data_fails(multi_chunk_ciphertext):
    with pytest.raises(KnfError, match="Decryption failed"):
        knf.decrypt(KEY, multi_chunk_ciphertext + b"\x00")


def test_bad_magic_and_reserved_and_chunk_size(multi_chunk_ciphertext):
    with pytest.raises(KnfError, match="Not a KNF1"):
        knf.decrypt(KEY, b"KNF2" + multi_chunk_ciphertext[4:])
    with pytest.raises(KnfError, match="Not a KNF1"):
        knf.decrypt(KEY, multi_chunk_ciphertext[:15] + b"\x01" + multi_chunk_ciphertext[16:])
    with pytest.raises(KnfError, match="Invalid chunk size"):
        knf.decrypt(KEY, b"KNF1" + struct.pack(">I", 1024) + multi_chunk_ciphertext[8:])


def test_decryptor_cannot_be_reused(multi_chunk_ciphertext):
    decryptor = knf.Decryptor(KEY)
    decryptor.push(multi_chunk_ciphertext)
    decryptor.finish()
    with pytest.raises(KnfError, match="already finished"):
        decryptor.push(b"x")
    with pytest.raises(KnfError, match="already finished"):
        decryptor.finish()


def test_unknown_kind_rejected():
    # Forge a payload with a valid AEAD but an unknown kind byte by sealing a custom stream.
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    header = b"KNF1" + struct.pack(">I", 4096) + PREFIX + b"\x00"
    meta = b"\x09\x00\x00\x00\x00"
    stream = struct.pack(">I", len(meta)) + meta + b"data"
    sealed = AESGCM(KEY).encrypt(PREFIX + struct.pack(">I", 0) + b"\x01", stream, header)
    with pytest.raises(KnfError, match="Unknown content kind"):
        knf.decrypt(KEY, header + sealed)


def test_inconsistent_metadata_length_rejected():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    header = b"KNF1" + struct.pack(">I", 4096) + PREFIX + b"\x00"
    meta = b"\x02\x00\x01a\x00\x05x"  # declares a 5-byte MIME but carries 1 byte
    stream = struct.pack(">I", len(meta)) + meta
    sealed = AESGCM(KEY).encrypt(PREFIX + struct.pack(">I", 0) + b"\x01", stream, header)
    with pytest.raises(KnfError, match="Metadata length mismatch"):
        knf.decrypt(KEY, header + sealed)


# ---------------------------------------------------------------------------
# Metadata limits, keys, sizes, links
# ---------------------------------------------------------------------------


def test_metadata_name_limit_is_utf8_bytes():
    knf.encode_metadata("file", "a" * 1024)
    knf.encode_metadata("file", "ü" * 512)  # 1024 bytes
    with pytest.raises(KnfError, match="File name exceeds 1024 bytes"):
        knf.encode_metadata("file", "ü" * 513)


def test_metadata_mime_limit():
    knf.encode_metadata("file", "a", "m" * 255)
    with pytest.raises(KnfError, match="MIME type exceeds 255 bytes"):
        knf.encode_metadata("file", "a", "m" * 256)


def test_metadata_text_carries_no_name_or_mime():
    assert knf.encode_metadata("text") == b"\x01\x00\x00\x00\x00"
    with pytest.raises(KnfError, match="must not carry"):
        knf.encode_metadata("text", "a")


def test_metadata_unknown_kind():
    with pytest.raises(KnfError, match="Unknown content kind"):
        knf.encode_metadata("image")  # type: ignore[arg-type]


def test_text_has_no_size_limit_in_format():
    text = "x" * 200_000
    assert knf.decrypt(KEY, knf.encrypt_text(KEY, text, chunk_size=4096)).text == text


def test_max_ciphertext_sizes():
    assert knf.max_file_ciphertext_size(0) == 16 + 4 + 5 + 1024 + 255 + 16
    assert knf.max_text_ciphertext_size(10) == 16 + 4 + 5 + 10 + 16
    assert knf.ciphertext_size(5, knf.DEFAULT_CHUNK_SIZE) == 16 + 4 + 5 + knf.DEFAULT_CHUNK_SIZE + 32


def test_invalid_chunk_size():
    with pytest.raises(KnfError, match="Invalid chunk size"):
        knf.encrypt(KEY, b"", kind="text", chunk_size=4095)
    with pytest.raises(KnfError, match="Invalid chunk size"):
        knf.ciphertext_size(5, 0, knf.MAX_CHUNK_SIZE + 1)


def test_invalid_key_and_nonce_prefix():
    with pytest.raises(KnfError, match="32 bytes"):
        knf.encrypt(b"short", b"", kind="text")
    with pytest.raises(KnfError, match="7 bytes"):
        knf.encrypt(KEY, b"", kind="text", _nonce_prefix=b"123")
    with pytest.raises(KnfError, match="32 bytes"):
        knf.Decryptor(b"short")


def test_generate_and_encode_key():
    key = knf.generate_key()
    assert len(key) == 32
    assert key != knf.generate_key()
    encoded = knf.encode_key(key)
    assert len(encoded) == 43
    assert "=" not in encoded and "+" not in encoded and "/" not in encoded
    assert knf.decode_key(encoded) == key


@pytest.mark.parametrize(
    "encoded",
    [
        "",
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh",
        "A+ECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
    ],
)
def test_decode_key_rejects_bad_encoding(encoded):
    with pytest.raises(KnfError, match="Invalid key"):
        knf.decode_key(encoded)


def test_build_and_parse_share_url():
    url = knf.build_share_url("https://download.konfidant.app/#t=abc%2Bdef%3D", KEY)
    assert url == "https://download.konfidant.app/#t=abc%2Bdef%3D&k=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
    parsed = knf.parse_share_url(url)
    assert parsed.origin == "https://download.konfidant.app"
    assert parsed.token == "abc+def="
    assert parsed.key == KEY


def test_build_share_url_requires_token_fragment():
    with pytest.raises(KnfError, match="#t="):
        knf.build_share_url("https://download.konfidant.app/", KEY)


@pytest.mark.parametrize(
    "url",
    [
        "https://download.konfidant.app/#t=abc",
        "https://download.konfidant.app/#k=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
        "https://download.konfidant.app/?t=abc&k=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
        "ftp://download.konfidant.app/#t=abc&k=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
        "/#t=abc&k=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
    ],
)
def test_parse_share_url_rejects_incomplete_links(url):
    with pytest.raises(KnfError):
        knf.parse_share_url(url)


def test_source_length():
    assert knf.source_length(b"abc") == 3
    assert knf.source_length(memoryview(b"abcd")) == 4
    stream = io.BytesIO(b"abcdef")
    stream.read(2)
    assert knf.source_length(stream) == 4
    assert stream.tell() == 2

    class Unseekable(io.RawIOBase):
        def readable(self):
            return True

    assert knf.source_length(Unseekable()) is None  # type: ignore[arg-type]
