"""KNF1 — Konfidant client-side encryption format.

Content is encrypted on the sender's machine with a random 256-bit key. The key travels only in the share link's
URL fragment (``#…``), which is never sent to a server, so Konfidant stores and delivers ciphertext it cannot read.

Layout (see the KNF1 specification)::

    ciphertext = header (16) || sealed_chunk_0 || … || sealed_chunk_n
    header     = "KNF1" || uint32_be(chunk_size) || nonce_prefix (7) || 0x00
    stream     = uint32_be(len(meta)) || meta || content
    meta       = kind (1) || uint16_be(len(name)) || name || uint16_be(len(mime)) || mime
    nonce_i    = nonce_prefix (7) || uint32_be(i) || last_flag (1)
    sealed_i   = AES-256-GCM(key, nonce_i, chunk_i, aad=header)
"""

from __future__ import annotations

import base64
import binascii
import io
import math
import os
import re
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from typing import BinaryIO, Literal
from urllib.parse import parse_qs, urlsplit

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"KNF1"
HEADER_SIZE = 16
TAG_SIZE = 16
KEY_SIZE = 32
NONCE_PREFIX_SIZE = 7
DEFAULT_CHUNK_SIZE = 1024 * 1024
MIN_CHUNK_SIZE = 4096
MAX_CHUNK_SIZE = 16 * 1024 * 1024
MAX_NAME_BYTES = 1024
MAX_MIME_BYTES = 255

_KIND_TEXT = 1
_KIND_FILE = 2
_META_FIXED_SIZE = 5  # kind (1) + name length (2) + mime length (2)
_META_LENGTH_PREFIX = 4
_MAX_CHUNK_INDEX = 0xFFFFFFFF
_KEY_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")

Kind = Literal["text", "file"]
Source = bytes | bytearray | memoryview | BinaryIO


class KnfError(Exception):
    """Raised for invalid input, malformed ciphertext or failed authentication."""


@dataclass(frozen=True)
class KnfDecrypted:
    kind: Kind
    name: str
    mime: str
    data: bytes

    @property
    def text(self) -> str:
        """The decoded UTF-8 text of a text share."""
        if self.kind != "text":
            raise KnfError("Share is not a text share")
        try:
            return self.data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise KnfError("Text share is not valid UTF-8") from exc


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------


def generate_key() -> bytes:
    """Returns 32 random bytes from the operating system CSPRNG. Use one key per share."""
    return os.urandom(KEY_SIZE)


def encode_key(key: bytes) -> str:
    """Encodes a key as unpadded base64url (43 characters)."""
    _check_key(key)
    return base64.urlsafe_b64encode(key).rstrip(b"=").decode("ascii")


def decode_key(encoded: str) -> bytes:
    """Decodes an unpadded base64url key (43 characters)."""
    if not isinstance(encoded, str) or not _KEY_PATTERN.match(encoded):
        raise KnfError("Invalid key encoding")
    try:
        key = base64.urlsafe_b64decode(encoded + "=")
    except (binascii.Error, ValueError) as exc:
        raise KnfError("Invalid key encoding") from exc
    if len(key) != KEY_SIZE:
        raise KnfError("Invalid key length")
    return key


def _check_key(key: bytes) -> None:
    if not isinstance(key, (bytes, bytearray)) or len(key) != KEY_SIZE:
        raise KnfError("Key must be 32 bytes")


# ---------------------------------------------------------------------------
# Metadata and sizes
# ---------------------------------------------------------------------------


def encode_metadata(kind: Kind, name: str = "", mime: str = "") -> bytes:
    """Encodes the metadata block. Names are limited to 1024 UTF-8 bytes, MIME types to 255; texts carry neither."""
    if kind not in ("text", "file"):
        raise KnfError("Unknown content kind")
    name_bytes = name.encode("utf-8")
    mime_bytes = mime.encode("utf-8")
    if kind == "text" and (name_bytes or mime_bytes):
        raise KnfError("Text shares must not carry a name or MIME type")
    if len(name_bytes) > MAX_NAME_BYTES:
        raise KnfError(f"File name exceeds {MAX_NAME_BYTES} bytes")
    if len(mime_bytes) > MAX_MIME_BYTES:
        raise KnfError(f"MIME type exceeds {MAX_MIME_BYTES} bytes")
    return (
        bytes([_KIND_TEXT if kind == "text" else _KIND_FILE])
        + struct.pack(">H", len(name_bytes))
        + name_bytes
        + struct.pack(">H", len(mime_bytes))
        + mime_bytes
    )


def _decode_metadata(meta: bytes) -> tuple[Kind, str, str]:
    if len(meta) < _META_FIXED_SIZE:
        raise KnfError("Metadata truncated")
    kind_byte = meta[0]
    if kind_byte not in (_KIND_TEXT, _KIND_FILE):
        raise KnfError("Unknown content kind")
    (name_length,) = struct.unpack_from(">H", meta, 1)
    if 3 + name_length + 2 > len(meta):
        raise KnfError("Metadata truncated")
    (mime_length,) = struct.unpack_from(">H", meta, 3 + name_length)
    if _META_FIXED_SIZE + name_length + mime_length != len(meta):
        raise KnfError("Metadata length mismatch")
    try:
        name = meta[3 : 3 + name_length].decode("utf-8")
        mime = meta[5 + name_length :].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise KnfError("Metadata is not valid UTF-8") from exc
    kind: Kind = "text" if kind_byte == _KIND_TEXT else "file"
    return kind, name, mime


def ciphertext_size(metadata_length: int, content_length: int, chunk_size: int = DEFAULT_CHUNK_SIZE) -> int:
    """Exact KNF1 ciphertext size for a metadata block and content of the given lengths."""
    _check_chunk_size(chunk_size)
    if metadata_length < 0 or content_length < 0:
        raise KnfError("Lengths must not be negative")
    stream_length = _META_LENGTH_PREFIX + metadata_length + content_length
    return HEADER_SIZE + stream_length + TAG_SIZE * math.ceil(stream_length / chunk_size)


def max_file_ciphertext_size(max_content_bytes: int) -> int:
    """Largest ciphertext a file of at most ``max_content_bytes`` can produce (longest name and MIME type)."""
    return ciphertext_size(_META_FIXED_SIZE + MAX_NAME_BYTES + MAX_MIME_BYTES, max_content_bytes)


def max_text_ciphertext_size(max_text_bytes: int) -> int:
    """Largest ciphertext a text of at most ``max_text_bytes`` UTF-8 bytes can produce."""
    return ciphertext_size(_META_FIXED_SIZE, max_text_bytes)


def _check_chunk_size(chunk_size: int) -> None:
    if not isinstance(chunk_size, int) or not MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE:
        raise KnfError("Invalid chunk size")


def _chunk_nonce(nonce_prefix: bytes, index: int, last: bool) -> bytes:
    if index > _MAX_CHUNK_INDEX:
        raise KnfError("Too many chunks")
    return nonce_prefix + struct.pack(">I", index) + (b"\x01" if last else b"\x00")


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------


def _reader(source: Source) -> Iterator[bytes]:
    """Yields content in pieces of arbitrary size; empty pieces are skipped."""
    if isinstance(source, (bytes, bytearray, memoryview)):
        view = memoryview(source).cast("B")
        step = DEFAULT_CHUNK_SIZE
        for offset in range(0, len(view), step):
            yield bytes(view[offset : offset + step])
        return
    if not hasattr(source, "read"):
        raise TypeError("source must be bytes or a binary file object")
    while True:
        piece = source.read(DEFAULT_CHUNK_SIZE)
        if piece is None:  # non-blocking stream with no data available
            raise KnfError("Non-blocking streams are not supported")
        if isinstance(piece, str):
            raise TypeError("source must be opened in binary mode")
        if not piece:
            return
        yield bytes(piece)


def _rechunk(pieces: Iterator[bytes], first: bytes, chunk_size: int) -> Iterator[bytes]:
    """Concatenates ``first`` and ``pieces`` and re-splits them into chunks of exactly ``chunk_size`` (last shorter)."""
    buffer = bytearray(first)
    for piece in pieces:
        buffer += piece
        while len(buffer) >= chunk_size:
            yield bytes(buffer[:chunk_size])
            del buffer[:chunk_size]
    if buffer:
        yield bytes(buffer)


def encrypt_stream(
    key: bytes,
    source: Source,
    *,
    kind: Kind,
    name: str = "",
    mime: str = "",
    content_length: int | None = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    _nonce_prefix: bytes | None = None,
) -> Iterator[bytes]:
    """Encrypts ``source`` (bytes or a binary file object) and yields the KNF1 header followed by sealed chunks.

    Holds at most two plaintext chunks in memory. When ``content_length`` is given, a source that yields a different
    number of bytes raises :class:`KnfError` (the declared upload size would otherwise not match).

    ``_nonce_prefix`` exists only to reproduce test vectors. Never pass it in production.
    """
    _check_key(key)
    _check_chunk_size(chunk_size)
    if _nonce_prefix is None:
        nonce_prefix = os.urandom(NONCE_PREFIX_SIZE)
    else:
        nonce_prefix = bytes(_nonce_prefix)
        if len(nonce_prefix) != NONCE_PREFIX_SIZE:
            raise KnfError("Nonce prefix must be 7 bytes")

    meta = encode_metadata(kind, name, mime)
    prefix = struct.pack(">I", len(meta)) + meta
    header = MAGIC + struct.pack(">I", chunk_size) + nonce_prefix + b"\x00"
    aead = AESGCM(bytes(key))

    def generate() -> Iterator[bytes]:
        yield header
        content_read = 0

        def counted(pieces: Iterator[bytes]) -> Iterator[bytes]:
            nonlocal content_read
            for piece in pieces:
                content_read += len(piece)
                yield piece

        chunks = _rechunk(counted(_reader(source)), prefix, chunk_size)
        # The stream is never empty (the metadata prefix is at least 9 bytes), so there is always a first chunk.
        pending = next(chunks)
        index = 0
        for upcoming in chunks:
            yield aead.encrypt(_chunk_nonce(nonce_prefix, index, False), pending, header)
            pending = upcoming
            index += 1
        if content_length is not None and content_read != content_length:
            raise KnfError(f"Source yielded {content_read} bytes, expected {content_length}")
        yield aead.encrypt(_chunk_nonce(nonce_prefix, index, True), pending, header)

    return generate()


def encrypt(
    key: bytes,
    source: Source,
    *,
    kind: Kind,
    name: str = "",
    mime: str = "",
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    _nonce_prefix: bytes | None = None,
) -> bytes:
    """Encrypts ``source`` into a complete KNF1 ciphertext."""
    return b"".join(
        encrypt_stream(key, source, kind=kind, name=name, mime=mime, chunk_size=chunk_size, _nonce_prefix=_nonce_prefix)
    )


def encrypt_text(
    key: bytes, text: str, *, chunk_size: int = DEFAULT_CHUNK_SIZE, _nonce_prefix: bytes | None = None
) -> bytes:
    """Encrypts a UTF-8 text share."""
    return encrypt(key, text.encode("utf-8"), kind="text", chunk_size=chunk_size, _nonce_prefix=_nonce_prefix)


# ---------------------------------------------------------------------------
# Decryption
# ---------------------------------------------------------------------------


class Decryptor:
    """Incremental decryptor: :meth:`push` bytes as they arrive, then :meth:`finish`.

    A full-size sealed chunk is opened as non-final only once at least one more byte has arrived; at end of input the
    buffered chunk is opened with the "last" flag. This is what detects truncated ciphertext.
    """

    def __init__(self, key: bytes) -> None:
        _check_key(key)
        self._aead = AESGCM(bytes(key))
        self._header: bytes | None = None
        self._chunk_size = 0
        self._buffer = bytearray()
        self._index = 0
        self._plaintext: list[bytes] = []
        self._finished = False

    def push(self, data: bytes) -> None:
        if self._finished:
            raise KnfError("Decryptor already finished")
        self._buffer += data

        if self._header is None:
            if len(self._buffer) < HEADER_SIZE:
                return
            header = bytes(self._buffer[:HEADER_SIZE])
            if header[:4] != MAGIC or header[15] != 0:
                raise KnfError("Not a KNF1 payload")
            (chunk_size,) = struct.unpack_from(">I", header, 4)
            if not MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE:
                raise KnfError("Invalid chunk size")
            self._header = header
            self._chunk_size = chunk_size
            del self._buffer[:HEADER_SIZE]

        sealed_chunk_size = self._chunk_size + TAG_SIZE
        # Keep at least one byte beyond a full chunk before opening it as non-final.
        while len(self._buffer) > sealed_chunk_size:
            self._open(bytes(self._buffer[:sealed_chunk_size]), last=False)
            del self._buffer[:sealed_chunk_size]

    def finish(self) -> KnfDecrypted:
        if self._finished:
            raise KnfError("Decryptor already finished")
        if self._header is None or len(self._buffer) <= TAG_SIZE:
            raise KnfError("Ciphertext truncated")
        self._open(bytes(self._buffer), last=True)
        self._finished = True
        self._buffer = bytearray()

        stream = b"".join(self._plaintext)
        self._plaintext = []
        if len(stream) < _META_LENGTH_PREFIX:
            raise KnfError("Metadata truncated")
        (meta_length,) = struct.unpack_from(">I", stream, 0)
        meta_end = _META_LENGTH_PREFIX + meta_length
        if meta_end > len(stream):
            raise KnfError("Metadata truncated")
        kind, name, mime = _decode_metadata(stream[_META_LENGTH_PREFIX:meta_end])
        return KnfDecrypted(kind=kind, name=name, mime=mime, data=stream[meta_end:])

    def _open(self, sealed: bytes, *, last: bool) -> None:
        header = self._header
        assert header is not None
        try:
            opened = self._aead.decrypt(_chunk_nonce(header[8:15], self._index, last), sealed, header)
        except InvalidTag as exc:
            # Fatal: drop everything decrypted so far.
            self._plaintext = []
            self._finished = True
            raise KnfError("Decryption failed: wrong key or corrupted or truncated ciphertext") from exc
        self._plaintext.append(opened)
        self._index += 1


def decrypt(key: bytes, ciphertext: bytes | bytearray | memoryview | BinaryIO) -> KnfDecrypted:
    """Decrypts a complete KNF1 ciphertext (bytes or a binary file object)."""
    decryptor = Decryptor(key)
    if isinstance(ciphertext, (bytes, bytearray, memoryview)):
        decryptor.push(bytes(ciphertext))
    else:
        for piece in _reader(ciphertext):
            decryptor.push(piece)
    return decryptor.finish()


# ---------------------------------------------------------------------------
# Share links
# ---------------------------------------------------------------------------


def build_share_url(download_url: str, key: bytes) -> str:
    """Appends the key to a server-issued download URL (which already carries ``#t=<token>`` in its fragment)."""
    if "#t=" not in download_url:
        raise KnfError("download_url must carry a #t= token fragment")
    return f"{download_url}&k={encode_key(key)}"


@dataclass(frozen=True)
class ParsedShareUrl:
    origin: str
    token: str
    key: bytes


def parse_share_url(share_url: str) -> ParsedShareUrl:
    """Parses ``https://<host>/#t=<token>&k=<key>`` into the link origin, token and key."""
    parts = urlsplit(share_url)
    if parts.scheme not in ("https", "http") or not parts.netloc:
        raise KnfError("Share URL must be an absolute http(s) URL")
    params = parse_qs(parts.fragment, keep_blank_values=False)
    tokens = params.get("t")
    keys = params.get("k")
    if not tokens or not keys:
        raise KnfError("Share URL is missing the token or key")
    return ParsedShareUrl(origin=f"{parts.scheme}://{parts.netloc}", token=tokens[0], key=decode_key(keys[0]))


def source_length(source: Source) -> int | None:
    """Remaining length of ``source`` without consuming it, or ``None`` when it cannot be determined."""
    if isinstance(source, (bytes, bytearray)):
        return len(source)
    if isinstance(source, memoryview):
        return source.nbytes
    try:
        if not source.seekable():
            return None
        position = source.tell()
        end = source.seek(0, io.SEEK_END)
        source.seek(position, io.SEEK_SET)
    except (AttributeError, OSError, ValueError):
        return None
    return max(end - position, 0)
