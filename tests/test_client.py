import base64
import io
import json
from urllib.parse import quote

import httpx
import pytest
import respx

from konfidant import KonfidantApiError, KonfidantClient, knf
from konfidant.types import (
    CompletedFileUpload,
    FileUpload,
    ListSharesResponse,
    OpenedShare,
    ShareFileResult,
    ShareTextResult,
)

BASE_URL = "http://api.test"
UPLOAD_URL = "http://r2.test/bucket/abc123.knf?X-Amz-Signature=sig"
DOWNLOAD_HOST = "https://download.test"
TOKEN = "tok+en/with=chars"
DOWNLOAD_URL = f"{DOWNLOAD_HOST}/#t={quote(TOKEN, safe='')}"
UPLOAD_HEADERS = {"Content-Type": "application/octet-stream", "x-amz-meta-org": "org-1"}


@pytest.fixture
def client():
    return KonfidantClient(api_key="test-key", base_url=BASE_URL)


def files_json() -> dict:
    return {
        "upload_url": UPLOAD_URL,
        "file_key": "abc123.knf",
        "upload_headers": UPLOAD_HEADERS,
        "upload_expires_in": 900,
    }


def complete_json(verified_burn: bool = True) -> dict:
    return {
        "download_url": DOWNLOAD_URL,
        "file_id": "file-1",
        "expires_at": "2026-10-05T00:00:00.000Z",
        "verified_burn": verified_burn,
    }


def key_from_share_url(share_url: str) -> bytes:
    return knf.parse_share_url(share_url).key


# ---------------------------------------------------------------------------
# Constructor
# ---------------------------------------------------------------------------


def test_new_missing_api_key():
    with pytest.raises(ValueError, match="api_key is required"):
        KonfidantClient(api_key="")


def test_new_strips_trailing_slash():
    c = KonfidantClient(api_key="k", base_url="http://example.com/")
    assert c._base_url == "http://example.com"


def test_new_default_base_url():
    c = KonfidantClient(api_key="k")
    assert c._base_url == "https://www.konfidant.app"


def test_new_custom_timeout():
    c = KonfidantClient(api_key="k", timeout=30.0)
    assert c._http.timeout.read == 30.0


def test_new_disabled_timeout():
    c = KonfidantClient(api_key="k", timeout=None)
    assert c._http.timeout.read is None


def test_context_manager_closes_http_client():
    with KonfidantClient(api_key="k") as c:
        pass
    assert c._http.is_closed


# ---------------------------------------------------------------------------
# share_text
# ---------------------------------------------------------------------------


@respx.mock
def test_share_text_sends_only_ciphertext(client):
    route = respx.post(f"{BASE_URL}/api/v1/texts").mock(
        return_value=httpx.Response(
            201,
            json={"download_url": DOWNLOAD_URL, "text_id": "text-1", "expires_at": "2026-10-04T00:00:00.000Z"},
        )
    )
    result = client.share_text("top secret", ttl_hours=24)

    assert route.called
    request = route.calls.last.request
    assert request.headers["authorization"] == "Bearer test-key"
    body = json.loads(request.content)
    assert set(body) == {"ciphertext", "ttl_hours"}
    assert body["ttl_hours"] == 24
    assert b"top secret" not in request.content

    # Standard base64 with padding of a KNF1 payload.
    ciphertext = base64.b64decode(body["ciphertext"], validate=True)
    assert body["ciphertext"] == base64.b64encode(ciphertext).decode()
    assert ciphertext[:4] == b"KNF1"

    assert isinstance(result, ShareTextResult)
    assert result.text_id == "text-1"
    assert result.expires_at == "2026-10-04T00:00:00.000Z"
    assert result.share_url.startswith(DOWNLOAD_URL + "&k=")
    key_part = result.share_url[len(DOWNLOAD_URL + "&k=") :]
    assert len(key_part) == 43
    # The key never reaches the server, but it decrypts what the server received.
    assert key_part not in request.content.decode()
    decrypted = knf.decrypt(key_from_share_url(result.share_url), ciphertext)
    assert (decrypted.kind, decrypted.text) == ("text", "top secret")


@respx.mock
def test_share_text_omits_ttl_when_none_and_allows_null_text_id(client):
    route = respx.post(f"{BASE_URL}/api/v1/texts").mock(
        return_value=httpx.Response(201, json={"download_url": DOWNLOAD_URL, "text_id": None, "expires_at": "x"})
    )
    result = client.share_text("hi")
    assert "ttl_hours" not in json.loads(route.calls.last.request.content)
    assert result.text_id is None


@respx.mock
def test_share_text_uses_fresh_key_per_share(client):
    respx.post(f"{BASE_URL}/api/v1/texts").mock(
        return_value=httpx.Response(201, json={"download_url": DOWNLOAD_URL, "text_id": "t", "expires_at": "x"})
    )
    assert client.share_text("a").share_url != client.share_text("a").share_url


@respx.mock
def test_share_text_api_error_401(client):
    respx.post(f"{BASE_URL}/api/v1/texts").mock(
        return_value=httpx.Response(401, json={"error": "unauthorized", "message": "Missing or invalid API key."})
    )
    with pytest.raises(KonfidantApiError) as exc_info:
        client.share_text("secret", ttl_hours=24)
    assert exc_info.value.status_code == 401
    assert str(exc_info.value) == "unauthorized"
    assert exc_info.value.body == {"error": "unauthorized", "message": "Missing or invalid API key."}


@respx.mock
def test_share_text_fallback_message_on_non_json(client):
    respx.post(f"{BASE_URL}/api/v1/texts").mock(return_value=httpx.Response(502, text="Bad Gateway"))
    with pytest.raises(KonfidantApiError) as exc_info:
        client.share_text("secret")
    assert exc_info.value.status_code == 502
    assert str(exc_info.value) == "HTTP 502"
    assert exc_info.value.body == "Bad Gateway"


# ---------------------------------------------------------------------------
# Low-level file upload
# ---------------------------------------------------------------------------


@respx.mock
def test_create_file_upload(client):
    route = respx.post(f"{BASE_URL}/api/v1/files").mock(return_value=httpx.Response(201, json=files_json()))
    upload = client.create_file_upload(1234, ttl_hours=48)

    request = route.calls.last.request
    assert request.headers["authorization"] == "Bearer test-key"
    assert json.loads(request.content) == {"ciphertext_size": 1234, "ttl_hours": 48}
    assert upload == FileUpload(
        upload_url=UPLOAD_URL, file_key="abc123.knf", upload_headers=UPLOAD_HEADERS, upload_expires_in=900
    )


@respx.mock
def test_create_file_upload_omits_ttl_when_none(client):
    route = respx.post(f"{BASE_URL}/api/v1/files").mock(return_value=httpx.Response(201, json=files_json()))
    client.create_file_upload(1234)
    assert json.loads(route.calls.last.request.content) == {"ciphertext_size": 1234}


def test_create_file_upload_rejects_impossible_size(client):
    with pytest.raises(ValueError, match="too small"):
        client.create_file_upload(32)


@respx.mock
def test_create_file_upload_error(client):
    respx.post(f"{BASE_URL}/api/v1/files").mock(
        return_value=httpx.Response(413, json={"error": "file_too_large", "message": "Max 80 MB"})
    )
    with pytest.raises(KonfidantApiError) as exc_info:
        client.create_file_upload(10**10)
    assert exc_info.value.status_code == 413
    assert str(exc_info.value) == "file_too_large"


@respx.mock
def test_upload_ciphertext_sends_exact_headers_without_authorization(client):
    route = respx.put(UPLOAD_URL).mock(return_value=httpx.Response(200))
    upload = FileUpload(**files_json())
    client.upload_ciphertext(upload, b"KNF1" + b"\x00" * 60)

    request = route.calls.last.request
    assert "authorization" not in request.headers
    assert request.headers["content-type"] == "application/octet-stream"
    assert request.headers["x-amz-meta-org"] == "org-1"
    assert request.headers["content-length"] == "64"
    assert "transfer-encoding" not in request.headers
    assert request.content == b"KNF1" + b"\x00" * 60


@respx.mock
def test_upload_ciphertext_streams_iterable_with_content_length(client):
    route = respx.put(UPLOAD_URL).mock(return_value=httpx.Response(200))
    parts = [b"KNF1" + b"\x00" * 12, b"a" * 40, b"b" * 8]
    client.upload_ciphertext(FileUpload(**files_json()), iter(parts), ciphertext_size=64)

    request = route.calls.last.request
    assert request.headers["content-length"] == "64"
    assert "transfer-encoding" not in request.headers
    assert "authorization" not in request.headers
    assert request.read() == b"".join(parts)


def test_upload_ciphertext_iterable_requires_size(client):
    with pytest.raises(ValueError, match="ciphertext_size is required"):
        client.upload_ciphertext(FileUpload(**files_json()), iter([b"x"]))


def test_upload_ciphertext_size_mismatch_for_bytes(client):
    with pytest.raises(ValueError, match="does not match"):
        client.upload_ciphertext(FileUpload(**files_json()), b"x" * 64, ciphertext_size=65)


@respx.mock
def test_upload_ciphertext_iterable_size_mismatch(client):
    respx.put(UPLOAD_URL).mock(return_value=httpx.Response(200))
    with pytest.raises(knf.KnfError, match="declared 64"):
        client.upload_ciphertext(FileUpload(**files_json()), iter([b"x" * 10]), ciphertext_size=64)


def test_upload_ciphertext_conflicting_content_length_header(client):
    upload = FileUpload(**{**files_json(), "upload_headers": {"Content-Length": "10"}})
    with pytest.raises(ValueError, match="Content-Length"):
        client.upload_ciphertext(upload, b"x" * 64)


@respx.mock
def test_upload_ciphertext_failure(client):
    respx.put(UPLOAD_URL).mock(return_value=httpx.Response(403, text="SignatureDoesNotMatch"))
    with pytest.raises(KonfidantApiError) as exc_info:
        client.upload_ciphertext(FileUpload(**files_json()), b"x" * 64)
    assert exc_info.value.status_code == 403
    assert "file upload failed" in str(exc_info.value)
    assert exc_info.value.body == "SignatureDoesNotMatch"


@respx.mock
def test_complete_file_upload(client):
    route = respx.post(f"{BASE_URL}/api/v1/files/abc123.knf/complete").mock(
        return_value=httpx.Response(201, json=complete_json())
    )
    completed = client.complete_file_upload("abc123.knf")

    request = route.calls.last.request
    assert request.headers["authorization"] == "Bearer test-key"
    assert request.content == b""
    assert completed == CompletedFileUpload(
        download_url=DOWNLOAD_URL, file_id="file-1", expires_at="2026-10-05T00:00:00.000Z", verified_burn=True
    )


@respx.mock
def test_complete_file_upload_url_encodes_file_key(client):
    route = respx.post(f"{BASE_URL}/api/v1/files/org%2Fhas%20space.knf/complete").mock(
        return_value=httpx.Response(201, json={**complete_json(False), "file_id": None})
    )
    completed = client.complete_file_upload("org/has space.knf")
    assert route.called
    assert completed.file_id is None
    assert completed.verified_burn is False


@respx.mock
def test_complete_file_upload_409_upload_incomplete(client):
    respx.post(f"{BASE_URL}/api/v1/files/abc123.knf/complete").mock(
        return_value=httpx.Response(409, json={"error": "upload_incomplete"})
    )
    with pytest.raises(KonfidantApiError) as exc_info:
        client.complete_file_upload("abc123.knf")
    assert exc_info.value.status_code == 409
    assert str(exc_info.value) == "upload_incomplete"


# ---------------------------------------------------------------------------
# share_file
# ---------------------------------------------------------------------------


def mock_file_flow(verified_burn: bool = True):
    create = respx.post(f"{BASE_URL}/api/v1/files").mock(return_value=httpx.Response(201, json=files_json()))
    put = respx.put(UPLOAD_URL).mock(return_value=httpx.Response(200))
    complete = respx.post(f"{BASE_URL}/api/v1/files/abc123.knf/complete").mock(
        return_value=httpx.Response(201, json=complete_json(verified_burn))
    )
    return create, put, complete


@pytest.mark.parametrize("as_stream", [False, True])
@respx.mock
def test_share_file_end_to_end(client, as_stream):
    content = bytes(range(256)) * 9000  # > 2 default chunks
    create, put, complete = mock_file_flow()
    data = io.BytesIO(content) if as_stream else content

    result = client.share_file(data, "report.pdf", content_type="application/pdf", ttl_hours=48)

    create_body = json.loads(create.calls.last.request.content)
    meta_length = len(knf.encode_metadata("file", "report.pdf", "application/pdf"))
    expected_size = knf.ciphertext_size(meta_length, len(content))
    assert create_body == {"ciphertext_size": expected_size, "ttl_hours": 48}
    assert "filename" not in create_body and "file_size" not in create_body

    put_request = put.calls.last.request
    uploaded = put_request.read()
    assert "authorization" not in put_request.headers
    assert put_request.headers["content-length"] == str(expected_size)
    assert put_request.headers["content-type"] == "application/octet-stream"
    assert len(uploaded) == expected_size
    assert b"report.pdf" not in uploaded
    assert complete.called

    assert isinstance(result, ShareFileResult)
    assert result.file_id == "file-1"
    assert result.verified_burn is True
    assert result.expires_at == "2026-10-05T00:00:00.000Z"
    assert result.share_url.startswith(DOWNLOAD_URL + "&k=")

    decrypted = knf.decrypt(key_from_share_url(result.share_url), uploaded)
    assert (decrypted.kind, decrypted.name, decrypted.mime) == ("file", "report.pdf", "application/pdf")
    assert decrypted.data == content


@respx.mock
def test_share_file_from_current_position_of_file_object(client):
    _, put, _ = mock_file_flow()
    stream = io.BytesIO(b"HEADERpayload")
    stream.read(6)
    result = client.share_file(stream, "p.bin")
    decrypted = knf.decrypt(key_from_share_url(result.share_url), put.calls.last.request.read())
    assert decrypted.data == b"payload"
    assert decrypted.mime == ""


@respx.mock
def test_share_file_non_seekable_stream(client):
    class Pipe(io.RawIOBase):
        def __init__(self, data: bytes) -> None:
            self._data = io.BytesIO(data)

        def readable(self) -> bool:
            return True

        def readinto(self, buffer) -> int:  # type: ignore[no-untyped-def]
            chunk = self._data.read(min(len(buffer), 1000))
            buffer[: len(chunk)] = chunk
            return len(chunk)

    content = b"z" * 5000
    create, put, _ = mock_file_flow()
    result = client.share_file(Pipe(content), "pipe.txt", "text/plain")  # type: ignore[arg-type]
    meta_length = len(knf.encode_metadata("file", "pipe.txt", "text/plain"))
    assert json.loads(create.calls.last.request.content)["ciphertext_size"] == knf.ciphertext_size(
        meta_length, len(content)
    )
    decrypted = knf.decrypt(key_from_share_url(result.share_url), put.calls.last.request.read())
    assert decrypted.data == content


@respx.mock
def test_share_file_empty_file(client):
    _, put, _ = mock_file_flow(verified_burn=False)
    result = client.share_file(b"", "empty.txt")
    assert result.verified_burn is False
    assert knf.decrypt(key_from_share_url(result.share_url), put.calls.last.request.read()).data == b""


@respx.mock
def test_share_file_stops_on_upload_failure(client):
    respx.post(f"{BASE_URL}/api/v1/files").mock(return_value=httpx.Response(201, json=files_json()))
    respx.put(UPLOAD_URL).mock(return_value=httpx.Response(500, text="boom"))
    complete = respx.post(f"{BASE_URL}/api/v1/files/abc123.knf/complete")
    with pytest.raises(KonfidantApiError) as exc_info:
        client.share_file(b"data", "a.txt")
    assert exc_info.value.status_code == 500
    assert not complete.called


@respx.mock
def test_share_file_surfaces_409(client):
    respx.post(f"{BASE_URL}/api/v1/files").mock(return_value=httpx.Response(201, json=files_json()))
    respx.put(UPLOAD_URL).mock(return_value=httpx.Response(200))
    respx.post(f"{BASE_URL}/api/v1/files/abc123.knf/complete").mock(
        return_value=httpx.Response(409, json={"error": "upload_incomplete"})
    )
    with pytest.raises(KonfidantApiError) as exc_info:
        client.share_file(b"data", "a.txt")
    assert exc_info.value.status_code == 409


def test_share_file_validates_metadata_before_network(client):
    with respx.mock(assert_all_called=False) as router:
        route = router.post(f"{BASE_URL}/api/v1/files")
        with pytest.raises(knf.KnfError, match="File name exceeds"):
            client.share_file(b"x", "n" * 1025)
        with pytest.raises(knf.KnfError, match="MIME type exceeds"):
            client.share_file(b"x", "a", content_type="m" * 256)
        with pytest.raises(ValueError, match="filename is required"):
            client.share_file(b"x", "")
        assert not route.called


# ---------------------------------------------------------------------------
# open_share
# ---------------------------------------------------------------------------


KEY = bytes(range(32))


def share_url_for(key: bytes = KEY) -> str:
    return knf.build_share_url(DOWNLOAD_URL, key)


@respx.mock
def test_open_share_text(client):
    ciphertext = knf.encrypt_text(KEY, "hello there")
    route = respx.post(f"{DOWNLOAD_HOST}/api/download").mock(
        return_value=httpx.Response(200, content=ciphertext, headers={"content-type": "application/octet-stream"})
    )
    opened = client.open_share(share_url_for())

    request = route.calls.last.request
    assert json.loads(request.content) == {"t": TOKEN}
    assert "authorization" not in request.headers
    assert knf.encode_key(KEY) not in request.content.decode()
    assert opened == OpenedShare(kind="text", name="", mime="", data=b"hello there", text="hello there")


@respx.mock
def test_open_share_file_multi_chunk(client):
    content = bytes(range(256)) * 50
    ciphertext = knf.encrypt(KEY, content, kind="file", name="doc.pdf", mime="application/pdf", chunk_size=4096)
    respx.post(f"{DOWNLOAD_HOST}/api/download").mock(return_value=httpx.Response(200, content=ciphertext))
    opened = client.open_share(share_url_for())
    assert (opened.kind, opened.name, opened.mime, opened.text) == ("file", "doc.pdf", "application/pdf", None)
    assert opened.data == content


@respx.mock
def test_open_share_uses_link_origin_not_base_url(client):
    ciphertext = knf.encrypt_text(KEY, "x")
    route = respx.post("https://files.customer.example/api/download").mock(
        return_value=httpx.Response(200, content=ciphertext)
    )
    client.open_share(knf.build_share_url("https://files.customer.example/#t=abc", KEY))
    assert route.called


@respx.mock
def test_open_share_410(client):
    respx.post(f"{DOWNLOAD_HOST}/api/download").mock(
        return_value=httpx.Response(410, json={"error": "gone", "message": "This link was already used."})
    )
    with pytest.raises(KonfidantApiError) as exc_info:
        client.open_share(share_url_for())
    assert exc_info.value.status_code == 410
    assert str(exc_info.value) == "gone"


@respx.mock
def test_open_share_wrong_key(client):
    ciphertext = knf.encrypt_text(KEY, "secret")
    respx.post(f"{DOWNLOAD_HOST}/api/download").mock(return_value=httpx.Response(200, content=ciphertext))
    with pytest.raises(knf.KnfError, match="Decryption failed"):
        client.open_share(share_url_for(bytes(32)))


@respx.mock
def test_open_share_truncated_download(client):
    ciphertext = knf.encrypt(KEY, b"y" * 10_000, kind="file", name="a", chunk_size=4096)
    respx.post(f"{DOWNLOAD_HOST}/api/download").mock(
        return_value=httpx.Response(200, content=ciphertext[: knf.HEADER_SIZE + 4096 + knf.TAG_SIZE])
    )
    with pytest.raises(knf.KnfError, match="Decryption failed"):
        client.open_share(share_url_for())


def test_open_share_rejects_link_without_key(client):
    with pytest.raises(knf.KnfError, match="missing the token or key"):
        client.open_share(DOWNLOAD_URL)


# ---------------------------------------------------------------------------
# list_shares
# ---------------------------------------------------------------------------


def make_shares_body(**pagination_overrides) -> dict:
    pagination = {"total": 0, "limit": 20, "offset": 0, "has_more": False, **pagination_overrides}
    return {"shares": [], "pagination": pagination}


@respx.mock
def test_list_shares_no_params(client):
    route = respx.get(f"{BASE_URL}/api/v1/shares").mock(return_value=httpx.Response(200, json=make_shares_body()))
    result = client.list_shares()
    assert route.called
    assert route.calls.last.request.url.query == b""
    assert route.calls.last.request.headers["authorization"] == "Bearer test-key"
    assert isinstance(result, ListSharesResponse)


@respx.mock
def test_list_shares_with_all_params(client):
    route = respx.get(f"{BASE_URL}/api/v1/shares").mock(return_value=httpx.Response(200, json=make_shares_body()))
    client.list_shares(type="file", status="active", limit=10, offset=20)
    params = dict(route.calls.last.request.url.params)
    assert params == {"type": "file", "status": "active", "limit": "10", "offset": "20"}


@respx.mock
def test_list_shares_returns_shares_without_file_name(client):
    body = {
        "shares": [
            {
                "type": "file",
                "file_size_bytes": 2048,
                "created_at": "2026-10-01T00:00:00.000Z",
                "expires_at": "2026-10-02T00:00:00.000Z",
                "accessed_at": None,
                "created_by": "dev@example.com",
            },
            {
                "type": "text",
                "file_size_bytes": None,
                "created_at": "2026-10-01T00:00:00.000Z",
                "expires_at": "2026-10-02T00:00:00.000Z",
                "accessed_at": "2026-10-01T01:00:00.000Z",
                "created_by": None,
            },
        ],
        "pagination": {"total": 2, "limit": 20, "offset": 0, "has_more": False},
    }
    respx.get(f"{BASE_URL}/api/v1/shares").mock(return_value=httpx.Response(200, json=body))
    result = client.list_shares()

    assert len(result.shares) == 2
    first, second = result.shares
    assert not hasattr(first, "file_name")
    assert (first.type, first.file_size_bytes, first.accessed_at, first.created_by) == (
        "file",
        2048,
        None,
        "dev@example.com",
    )
    assert (second.type, second.accessed_at, second.created_by) == ("text", "2026-10-01T01:00:00.000Z", None)
    assert result.pagination.total == 2


@respx.mock
def test_list_shares_has_more_pagination(client):
    respx.get(f"{BASE_URL}/api/v1/shares").mock(
        return_value=httpx.Response(200, json=make_shares_body(total=50, limit=10, offset=0, has_more=True))
    )
    result = client.list_shares(limit=10)
    assert result.pagination.has_more is True
    assert result.pagination.total == 50


# ---------------------------------------------------------------------------
# Removed API surface
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["share_and_upload_file", "get_file_status", "upload_file"])
def test_obsolete_methods_removed(name):
    assert not hasattr(KonfidantClient, name)
