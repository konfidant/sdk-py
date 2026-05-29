import time
from typing import IO, Any, Optional
from urllib.parse import quote, urlencode

import httpx

from .errors import KonfidantApiError
from .types import (
    FileMetadataHeaders,
    FileStatusResponse,
    ListSharesResponse,
    Pagination,
    Share,
    ShareFileResponse,
    ShareResult,
    ShareTextResponse,
)

DEFAULT_BASE_URL = "https://www.konfidant.app"
DEFAULT_TIMEOUT = 120.0


class KonfidantClient:
    def __init__(
        self,
        api_key: str,
        base_url: str = DEFAULT_BASE_URL,
        timeout: Optional[float] = DEFAULT_TIMEOUT,
    ) -> None:
        if not api_key:
            raise ValueError("api_key is required")
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._http = httpx.Client(timeout=httpx.Timeout(timeout))

    def _auth_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        url = self._base_url + path
        headers = {**self._auth_headers(), **kwargs.pop("headers", {})}
        response = self._http.request(method, url, headers=headers, **kwargs)

        content_type = response.headers.get("content-type", "")
        if "application/json" in content_type:
            body: Any = response.json()
        else:
            body = response.text

        if not (200 <= response.status_code < 300):
            message = (
                body.get("error")
                if isinstance(body, dict) and "error" in body
                else f"HTTP {response.status_code}"
            )
            raise KonfidantApiError(message, response.status_code, body)

        return body

    def share_text(self, text: str, ttl_hours: int) -> ShareTextResponse:
        body = self._request("POST", "/api/v1/texts", json={"text": text, "ttl_hours": ttl_hours})
        return ShareTextResponse(
            text_id=body["text_id"],
            share_url=body["share_url"],
            expires_at=body["expires_at"],
            verified_burn=body["verified_burn"],
        )

    def share_file(self, filename: str, file_size: int, ttl_hours: int) -> ShareFileResponse:
        body = self._request(
            "POST",
            "/api/v1/files",
            json={"filename": filename, "file_size": file_size, "ttl_hours": ttl_hours},
        )
        h = body["metadata_headers"]
        return ShareFileResponse(
            upload_url=body["upload_url"],
            file_key=body["file_key"],
            metadata_headers=FileMetadataHeaders(
                user_id=h["x-amz-meta-user-id"],
                ttl_hours=h["x-amz-meta-ttl-hours"],
                organization_id=h["x-amz-meta-organization-id"],
            ),
            poll_url=body["poll_url"],
        )

    def get_file_status(self, file_key: str) -> FileStatusResponse:
        encoded = quote(file_key, safe="")
        body = self._request("GET", f"/api/v1/files/{encoded}/status")
        return FileStatusResponse(
            status=body["status"],
            message=body.get("message"),
            file_id=body.get("file_id"),
            file_name=body.get("file_name"),
            share_url=body.get("share_url"),
            expires_at=body.get("expires_at"),
            verified_burn=body.get("verified_burn"),
        )

    def list_shares(
        self,
        type: Optional[str] = None,
        status: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> ListSharesResponse:
        params: dict[str, str] = {}
        if type is not None:
            params["type"] = type
        if status is not None:
            params["status"] = status
        if limit is not None:
            params["limit"] = str(limit)
        if offset is not None:
            params["offset"] = str(offset)

        path = "/api/v1/shares"
        if params:
            path += "?" + urlencode(params)

        body = self._request("GET", path)
        return ListSharesResponse(
            shares=[
                Share(
                    type=s["type"],
                    file_name=s["file_name"],
                    file_size_bytes=s["file_size_bytes"],
                    created_at=s["created_at"],
                    expires_at=s["expires_at"],
                    accessed_at=s.get("accessed_at"),
                    created_by=s["created_by"],
                )
                for s in body["shares"]
            ],
            pagination=Pagination(
                total=body["pagination"]["total"],
                limit=body["pagination"]["limit"],
                offset=body["pagination"]["offset"],
                has_more=body["pagination"]["has_more"],
            ),
        )

    def upload_file(
        self,
        data: bytes | IO[bytes],
        size: int,
        content_type: str,
        presigned: ShareFileResponse,
    ) -> None:
        headers = {
            "Content-Type": content_type,
            "Content-Length": str(size),
            "x-amz-meta-organization-id": presigned.metadata_headers.organization_id,
            "x-amz-meta-ttl-hours": presigned.metadata_headers.ttl_hours,
            "x-amz-meta-user-id": presigned.metadata_headers.user_id,
        }
        response = self._http.put(presigned.upload_url, content=data, headers=headers)
        if not (200 <= response.status_code < 300):
            raise KonfidantApiError(
                f"file upload failed: HTTP {response.status_code}",
                response.status_code,
                response.text,
            )

    def share_and_upload_file(
        self,
        data: bytes | IO[bytes],
        size: int,
        filename: str,
        content_type: str,
        ttl_hours: int,
        poll_interval: float = 2.0,
        timeout: float = 60.0,
    ) -> ShareResult:
        presigned = self.share_file(filename=filename, file_size=size, ttl_hours=ttl_hours)
        self.upload_file(data=data, size=size, content_type=content_type, presigned=presigned)

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            file_status = self.get_file_status(presigned.file_key)
            if file_status.status == "complete":
                return ShareResult(
                    share_url=file_status.share_url,
                    file_id=file_status.file_id,
                    expires_at=file_status.expires_at,
                    verified_burn=file_status.verified_burn,
                )
            time.sleep(poll_interval)

        raise TimeoutError(f"konfidant: encryption timed out after {timeout}s")
