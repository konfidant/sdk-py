import io

import httpx
import pytest
import respx

from konfidant import KonfidantApiError, KonfidantClient
from konfidant.types import (
    FileMetadataHeaders,
    FileStatusResponse,
    ListSharesResponse,
    ShareFileResponse,
    ShareResult,
    ShareTextResponse,
)

BASE_URL = "http://api.test"


@pytest.fixture
def client():
    return KonfidantClient(api_key="test-key", base_url=BASE_URL)


def make_presigned(upload_url: str = "http://s3.test/upload") -> ShareFileResponse:
    return ShareFileResponse(
        upload_url=upload_url,
        file_key="abc123.zip",
        poll_url=f"{BASE_URL}/api/v1/files/abc123.zip/status",
        metadata_headers=FileMetadataHeaders(
            user_id="user-1",
            ttl_hours="48",
            organization_id="org-1",
        ),
    )


def presigned_json(upload_url: str = "http://s3.test/upload") -> dict:
    return {
        "upload_url": upload_url,
        "file_key": "abc123.zip",
        "poll_url": f"{BASE_URL}/api/v1/files/abc123.zip/status",
        "metadata_headers": {
            "x-amz-meta-user-id": "user-1",
            "x-amz-meta-ttl-hours": "48",
            "x-amz-meta-organization-id": "org-1",
        },
    }


# ---------------------------------------------------------------------------
# Constructor
# ---------------------------------------------------------------------------


def test_new_missing_api_key():
    with pytest.raises(ValueError, match="api_key is required"):
        KonfidantClient(api_key="")


def test_new_strips_trailing_slash():
    c = KonfidantClient(api_key="k", base_url="https://example.com/")
    assert c._base_url == "https://example.com"


def test_new_default_base_url():
    c = KonfidantClient(api_key="k")
    assert c._base_url == "https://www.konfidant.app"


def test_new_custom_timeout():
    c = KonfidantClient(api_key="k", timeout=5.0)
    assert c._http.timeout == httpx.Timeout(5.0)


def test_new_disabled_timeout():
    c = KonfidantClient(api_key="k", timeout=None)
    assert c._http.timeout == httpx.Timeout(None)


# ---------------------------------------------------------------------------
# share_text
# ---------------------------------------------------------------------------


@respx.mock
def test_share_text_success(client):
    expected = {
        "text_id": "abc",
        "share_url": "https://download.konfidant.app?t=tok",
        "expires_at": "2026-06-01 00:00:00",
        "verified_burn": True,
    }
    route = respx.post(f"{BASE_URL}/api/v1/texts").mock(
        return_value=httpx.Response(201, json=expected)
    )

    result = client.share_text(text="Secret", ttl_hours=24)

    assert route.called
    assert route.call_count == 1
    req = route.calls.last.request
    assert req.method == "POST"
    assert req.headers["Authorization"] == "Bearer test-key"
    assert result == ShareTextResponse(**expected)


@respx.mock
def test_share_text_sends_correct_body(client):
    respx.post(f"{BASE_URL}/api/v1/texts").mock(
        return_value=httpx.Response(
            201,
            json={"text_id": "x", "share_url": "x", "expires_at": "x", "verified_burn": False},
        )
    )
    client.share_text(text="Secret", ttl_hours=24)
    req = respx.calls.last.request
    import json
    body = json.loads(req.content)
    assert body == {"text": "Secret", "ttl_hours": 24}


@respx.mock
def test_share_text_api_error_401(client):
    respx.post(f"{BASE_URL}/api/v1/texts").mock(
        return_value=httpx.Response(
            401, json={"error": "Missing or invalid Authorization header."}
        )
    )
    with pytest.raises(KonfidantApiError) as exc_info:
        client.share_text(text="x", ttl_hours=1)
    err = exc_info.value
    assert err.status_code == 401
    assert "Missing or invalid Authorization header." in str(err)


@respx.mock
def test_share_text_api_error_400(client):
    respx.post(f"{BASE_URL}/api/v1/texts").mock(
        return_value=httpx.Response(400, json={"error": "Invalid JSON body"})
    )
    with pytest.raises(KonfidantApiError):
        client.share_text(text="", ttl_hours=0)


@respx.mock
def test_share_text_fallback_message_on_non_json(client):
    respx.post(f"{BASE_URL}/api/v1/texts").mock(
        return_value=httpx.Response(500, text="Internal Server Error")
    )
    with pytest.raises(KonfidantApiError) as exc_info:
        client.share_text(text="x", ttl_hours=1)
    assert exc_info.value.status_code == 500
    assert "HTTP 500" in str(exc_info.value)


# ---------------------------------------------------------------------------
# share_file
# ---------------------------------------------------------------------------


@respx.mock
def test_share_file_success(client):
    route = respx.post(f"{BASE_URL}/api/v1/files").mock(
        return_value=httpx.Response(202, json=presigned_json())
    )
    result = client.share_file(filename="doc.pdf", file_size=1024, ttl_hours=48)

    assert route.called
    assert result.file_key == "abc123.zip"
    assert result.upload_url == "http://s3.test/upload"
    assert result.metadata_headers.user_id == "user-1"
    assert result.metadata_headers.ttl_hours == "48"
    assert result.metadata_headers.organization_id == "org-1"


@respx.mock
def test_share_file_sends_correct_body(client):
    respx.post(f"{BASE_URL}/api/v1/files").mock(
        return_value=httpx.Response(202, json=presigned_json())
    )
    client.share_file(filename="doc.pdf", file_size=1024, ttl_hours=48)
    import json
    body = json.loads(respx.calls.last.request.content)
    assert body == {"filename": "doc.pdf", "file_size": 1024, "ttl_hours": 48}


@respx.mock
def test_share_file_unauthorized(client):
    respx.post(f"{BASE_URL}/api/v1/files").mock(
        return_value=httpx.Response(401, json={"error": "Unauthorized"})
    )
    with pytest.raises(KonfidantApiError) as exc_info:
        client.share_file(filename="x", file_size=1, ttl_hours=1)
    assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# get_file_status
# ---------------------------------------------------------------------------


@respx.mock
def test_get_file_status_processing(client):
    respx.get(f"{BASE_URL}/api/v1/files/abc123.zip/status").mock(
        return_value=httpx.Response(
            202, json={"status": "processing", "message": "Encryption in progress"}
        )
    )
    result = client.get_file_status("abc123.zip")
    assert result.status == "processing"
    assert result.message == "Encryption in progress"


@respx.mock
def test_get_file_status_complete(client):
    complete = {
        "status": "complete",
        "file_id": "file-1",
        "file_name": "doc.pdf",
        "share_url": "https://download.konfidant.app?t=tok",
        "expires_at": "2026-06-01 00:00:00",
        "verified_burn": True,
    }
    respx.get(f"{BASE_URL}/api/v1/files/abc123.zip/status").mock(
        return_value=httpx.Response(200, json=complete)
    )
    result = client.get_file_status("abc123.zip")
    assert result.status == "complete"
    assert result.file_id == "file-1"
    assert result.verified_burn is True


@respx.mock
def test_get_file_status_url_encodes_file_key(client):
    route = respx.get(f"{BASE_URL}/api/v1/files/has%20spaces.zip/status").mock(
        return_value=httpx.Response(
            200,
            json={"status": "complete", "file_id": "x", "file_name": "x", "share_url": "x", "expires_at": "x"},
        )
    )
    client.get_file_status("has spaces.zip")
    assert route.called


@respx.mock
def test_get_file_status_not_found(client):
    respx.get(f"{BASE_URL}/api/v1/files/nope/status").mock(
        return_value=httpx.Response(404, json={"error": "File not found"})
    )
    with pytest.raises(KonfidantApiError) as exc_info:
        client.get_file_status("nope")
    assert exc_info.value.status_code == 404


@respx.mock
def test_get_file_status_processing_fields_are_none(client):
    respx.get(f"{BASE_URL}/api/v1/files/abc123.zip/status").mock(
        return_value=httpx.Response(
            202, json={"status": "processing", "message": "Encryption in progress"}
        )
    )
    result = client.get_file_status("abc123.zip")
    assert result.file_id is None
    assert result.file_name is None
    assert result.share_url is None
    assert result.expires_at is None


# ---------------------------------------------------------------------------
# list_shares
# ---------------------------------------------------------------------------


@respx.mock
def test_list_shares_no_params(client):
    empty = {"shares": [], "pagination": {"total": 0, "limit": 50, "offset": 0, "has_more": False}}
    route = respx.get(f"{BASE_URL}/api/v1/shares").mock(
        return_value=httpx.Response(200, json=empty)
    )
    result = client.list_shares()
    assert route.called
    assert isinstance(result, ListSharesResponse)
    assert result.shares == []
    assert "?" not in str(route.calls.last.request.url)


@respx.mock
def test_list_shares_with_all_params(client):
    empty = {"shares": [], "pagination": {"total": 0, "limit": 10, "offset": 20, "has_more": False}}
    route = respx.get(f"{BASE_URL}/api/v1/shares").mock(
        return_value=httpx.Response(200, json=empty)
    )
    client.list_shares(type="file", status="active", limit=10, offset=20)
    url = str(route.calls.last.request.url)
    assert "type=file" in url
    assert "status=active" in url
    assert "limit=10" in url
    assert "offset=20" in url


@respx.mock
def test_list_shares_omits_absent_params(client):
    empty = {"shares": [], "pagination": {"total": 0, "limit": 50, "offset": 0, "has_more": False}}
    route = respx.get(f"{BASE_URL}/api/v1/shares").mock(
        return_value=httpx.Response(200, json=empty)
    )
    client.list_shares(type="text")
    url = str(route.calls.last.request.url)
    assert "type=text" in url
    assert "status" not in url
    assert "limit" not in url
    assert "offset" not in url


@respx.mock
def test_list_shares_returns_shares_and_pagination(client):
    body = {
        "shares": [
            {
                "type": "file",
                "file_name": "doc.pdf",
                "file_size_bytes": 1024,
                "created_at": "2026-05-01T00:00:00.000Z",
                "expires_at": "2026-05-08T00:00:00.000Z",
                "accessed_at": None,
                "created_by": "user@example.com",
            }
        ],
        "pagination": {"total": 1, "limit": 50, "offset": 0, "has_more": False},
    }
    respx.get(f"{BASE_URL}/api/v1/shares").mock(return_value=httpx.Response(200, json=body))

    result = client.list_shares()

    assert len(result.shares) == 1
    assert result.shares[0].file_name == "doc.pdf"
    assert result.shares[0].accessed_at is None
    assert result.pagination.total == 1
    assert result.pagination.has_more is False


@respx.mock
def test_list_shares_has_more_pagination(client):
    body = {
        "shares": [],
        "pagination": {"total": 100, "limit": 10, "offset": 0, "has_more": True},
    }
    respx.get(f"{BASE_URL}/api/v1/shares").mock(return_value=httpx.Response(200, json=body))

    result = client.list_shares(limit=10)

    assert result.pagination.has_more is True
    assert result.pagination.total == 100


@respx.mock
def test_list_shares_forbidden(client):
    respx.get(f"{BASE_URL}/api/v1/shares").mock(
        return_value=httpx.Response(
            403,
            json={
                "error": "Insufficient permissions",
                "required_scope": "shares:list",
                "available_scopes": ["files:create"],
            },
        )
    )
    with pytest.raises(KonfidantApiError) as exc_info:
        client.list_shares()
    assert exc_info.value.status_code == 403
    assert "Insufficient permissions" in str(exc_info.value)


# ---------------------------------------------------------------------------
# upload_file
# ---------------------------------------------------------------------------


@respx.mock
def test_upload_file_put_with_correct_headers(client):
    route = respx.put("http://s3.test/upload").mock(return_value=httpx.Response(200))
    presigned = make_presigned()

    client.upload_file(
        data=b"hello",
        size=5,
        content_type="text/plain",
        presigned=presigned,
    )

    assert route.called
    req = route.calls.last.request
    assert req.method == "PUT"
    assert req.headers["Content-Type"] == "text/plain"
    assert req.headers["x-amz-meta-organization-id"] == "org-1"
    assert req.headers["x-amz-meta-ttl-hours"] == "48"
    assert req.headers["x-amz-meta-user-id"] == "user-1"
    assert req.content == b"hello"


@respx.mock
def test_upload_file_no_auth_header_sent_to_s3(client):
    route = respx.put("http://s3.test/upload").mock(return_value=httpx.Response(200))
    client.upload_file(data=b"x", size=1, content_type="text/plain", presigned=make_presigned())

    req = route.calls.last.request
    assert "authorization" not in {k.lower() for k in req.headers}


@respx.mock
def test_upload_file_accepts_file_like_object(client):
    route = respx.put("http://s3.test/upload").mock(return_value=httpx.Response(200))
    client.upload_file(
        data=io.BytesIO(b"hello"),
        size=5,
        content_type="text/plain",
        presigned=make_presigned(),
    )
    assert route.called


@respx.mock
def test_upload_file_s3_error(client):
    respx.put("http://s3.test/upload").mock(return_value=httpx.Response(403, text="AccessDenied"))
    with pytest.raises(KonfidantApiError) as exc_info:
        client.upload_file(data=b"x", size=1, content_type="text/plain", presigned=make_presigned())
    assert exc_info.value.status_code == 403
    assert "file upload failed" in str(exc_info.value)


# ---------------------------------------------------------------------------
# share_and_upload_file
# ---------------------------------------------------------------------------


@respx.mock
def test_share_and_upload_file_success(client):
    processing = {"status": "processing", "message": "Encryption in progress"}
    complete = {
        "status": "complete",
        "file_id": "file-1",
        "file_name": "doc.pdf",
        "share_url": "https://download.konfidant.app?t=tok",
        "expires_at": "2026-06-01 00:00:00",
        "verified_burn": True,
    }

    respx.post(f"{BASE_URL}/api/v1/files").mock(
        return_value=httpx.Response(202, json=presigned_json())
    )
    respx.put("http://s3.test/upload").mock(return_value=httpx.Response(200))
    status_route = respx.get(f"{BASE_URL}/api/v1/files/abc123.zip/status").mock(
        side_effect=[
            httpx.Response(202, json=processing),
            httpx.Response(200, json=complete),
        ]
    )

    result = client.share_and_upload_file(
        data=b"data",
        size=4,
        filename="doc.pdf",
        content_type="application/pdf",
        ttl_hours=48,
        poll_interval=0.01,
        timeout=5.0,
    )

    assert isinstance(result, ShareResult)
    assert result.share_url == "https://download.konfidant.app?t=tok"
    assert result.file_id == "file-1"
    assert result.verified_burn is True
    assert status_route.call_count == 2


@respx.mock
def test_share_and_upload_file_timeout(client):
    processing = {"status": "processing", "message": "Encryption in progress"}

    respx.post(f"{BASE_URL}/api/v1/files").mock(
        return_value=httpx.Response(202, json=presigned_json())
    )
    respx.put("http://s3.test/upload").mock(return_value=httpx.Response(200))
    respx.get(f"{BASE_URL}/api/v1/files/abc123.zip/status").mock(
        return_value=httpx.Response(202, json=processing)
    )

    with pytest.raises(TimeoutError, match="timed out"):
        client.share_and_upload_file(
            data=b"data",
            size=4,
            filename="doc.pdf",
            content_type="application/pdf",
            ttl_hours=48,
            poll_interval=0.01,
            timeout=0.05,
        )


@respx.mock
def test_share_and_upload_file_propagates_share_file_error(client):
    respx.post(f"{BASE_URL}/api/v1/files").mock(
        return_value=httpx.Response(401, json={"error": "Unauthorized"})
    )
    with pytest.raises(KonfidantApiError) as exc_info:
        client.share_and_upload_file(
            data=b"data", size=4, filename="doc.pdf", content_type="application/pdf", ttl_hours=48
        )
    assert exc_info.value.status_code == 401


@respx.mock
def test_share_and_upload_file_propagates_upload_error(client):
    respx.post(f"{BASE_URL}/api/v1/files").mock(
        return_value=httpx.Response(202, json=presigned_json())
    )
    respx.put("http://s3.test/upload").mock(return_value=httpx.Response(403, text="AccessDenied"))
    with pytest.raises(KonfidantApiError) as exc_info:
        client.share_and_upload_file(
            data=b"data", size=4, filename="doc.pdf", content_type="application/pdf", ttl_hours=48
        )
    assert exc_info.value.status_code == 403


@respx.mock
def test_share_and_upload_file_propagates_status_error(client):
    respx.post(f"{BASE_URL}/api/v1/files").mock(
        return_value=httpx.Response(202, json=presigned_json())
    )
    respx.put("http://s3.test/upload").mock(return_value=httpx.Response(200))
    respx.get(f"{BASE_URL}/api/v1/files/abc123.zip/status").mock(
        return_value=httpx.Response(500, json={"error": "Internal Server Error"})
    )
    with pytest.raises(KonfidantApiError) as exc_info:
        client.share_and_upload_file(
            data=b"data",
            size=4,
            filename="doc.pdf",
            content_type="application/pdf",
            ttl_hours=48,
            timeout=5.0,
        )
    assert exc_info.value.status_code == 500


# ---------------------------------------------------------------------------
# KonfidantApiError
# ---------------------------------------------------------------------------


def test_api_error_fields():
    err = KonfidantApiError("Unauthorized", 401, {"error": "Unauthorized"})
    assert err.status_code == 401
    assert err.body == {"error": "Unauthorized"}
    assert str(err) == "Unauthorized"
    assert isinstance(err, Exception)


@respx.mock
def test_api_error_carries_body(client):
    respx.post(f"{BASE_URL}/api/v1/texts").mock(
        return_value=httpx.Response(401, json={"error": "Missing or invalid Authorization header."})
    )
    with pytest.raises(KonfidantApiError) as exc_info:
        client.share_text(text="x", ttl_hours=1)
    err = exc_info.value
    assert err.status_code == 401
    assert isinstance(err.body, dict)
    assert err.body["error"] == "Missing or invalid Authorization header."
