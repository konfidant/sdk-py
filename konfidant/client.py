import base64
from collections.abc import Iterable, Iterator
from typing import Any, BinaryIO, Self
from urllib.parse import quote, urlencode

import httpx

from . import knf
from .errors import KonfidantApiError
from .types import (
    CompletedFileUpload,
    FileUpload,
    ListSharesResponse,
    OpenedShare,
    Pagination,
    Share,
    ShareFileResult,
    ShareTextResult,
)

DEFAULT_BASE_URL = "https://www.konfidant.app"
DEFAULT_TIMEOUT = 120.0

Ciphertext = bytes | bytearray | memoryview | Iterable[bytes]


def _error_from_response(response: httpx.Response) -> KonfidantApiError:
    body: Any
    if "application/json" in response.headers.get("content-type", ""):
        try:
            body = response.json()
        except ValueError:
            body = response.text
    else:
        body = response.text
    if isinstance(body, dict) and isinstance(body.get("error"), str):
        message = body["error"]
    else:
        message = f"HTTP {response.status_code}"
    return KonfidantApiError(message, response.status_code, body)


class KonfidantClient:
    """Konfidant API client. All content is encrypted locally (KNF1); the server only ever receives ciphertext."""

    def __init__(
        self,
        api_key: str,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float | None = DEFAULT_TIMEOUT,
    ) -> None:
        if not api_key:
            raise ValueError("api_key is required")
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._http = httpx.Client(timeout=httpx.Timeout(timeout))

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Transport
    # ------------------------------------------------------------------

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Accept": "application/json",
            **kwargs.pop("headers", {}),
        }
        response = self._http.request(method, self._base_url + path, headers=headers, **kwargs)
        if not 200 <= response.status_code < 300:
            raise _error_from_response(response)
        if "application/json" in response.headers.get("content-type", ""):
            return response.json()
        return response.text

    # ------------------------------------------------------------------
    # Texts
    # ------------------------------------------------------------------

    def share_text(self, text: str, ttl_hours: int | None = None) -> ShareTextResult:
        """Encrypts ``text`` locally and returns a single-use share link carrying the key in its fragment."""
        key = knf.generate_key()
        ciphertext = knf.encrypt_text(key, text)
        payload: dict[str, Any] = {"ciphertext": base64.b64encode(ciphertext).decode("ascii")}
        if ttl_hours is not None:
            payload["ttl_hours"] = ttl_hours
        body = self._request("POST", "/api/v1/texts", json=payload)
        return ShareTextResult(
            share_url=knf.build_share_url(body["download_url"], key),
            text_id=body.get("text_id"),
            expires_at=body["expires_at"],
        )

    # ------------------------------------------------------------------
    # Files
    # ------------------------------------------------------------------

    def share_file(
        self,
        data: bytes | bytearray | memoryview | BinaryIO,
        filename: str,
        content_type: str = "",
        ttl_hours: int | None = None,
    ) -> ShareFileResult:
        """Encrypts a file locally, uploads the ciphertext and returns a single-use share link.

        ``data`` may be bytes or a binary file object (read from its current position). Seekable files are encrypted
        and streamed chunk by chunk; non-seekable streams are read into memory first because the exact ciphertext
        size must be declared before the upload.
        """
        if not filename:
            raise ValueError("filename is required")
        meta_length = len(knf.encode_metadata("file", filename, content_type))  # validates name/MIME limits

        source: knf.Source = data
        content_length = knf.source_length(data)
        if content_length is None:
            buffered = data.read()  # type: ignore[union-attr]
            if not isinstance(buffered, (bytes, bytearray)):
                raise TypeError("data must be bytes or a binary file object")
            source = bytes(buffered)
            content_length = len(source)

        size = knf.ciphertext_size(meta_length, content_length)
        key = knf.generate_key()
        upload = self.create_file_upload(size, ttl_hours=ttl_hours)
        ciphertext = knf.encrypt_stream(
            key,
            source,
            kind="file",
            name=filename,
            mime=content_type,
            content_length=content_length,
        )
        self.upload_ciphertext(upload, ciphertext, ciphertext_size=size)
        completed = self.complete_file_upload(upload.file_key)
        return ShareFileResult(
            share_url=knf.build_share_url(completed.download_url, key),
            file_id=completed.file_id,
            expires_at=completed.expires_at,
            verified_burn=completed.verified_burn,
        )

    def create_file_upload(self, ciphertext_size: int, ttl_hours: int | None = None) -> FileUpload:
        """Reserves an upload for a KNF1 ciphertext of exactly ``ciphertext_size`` bytes."""
        if ciphertext_size <= knf.HEADER_SIZE + knf.TAG_SIZE:
            raise ValueError("ciphertext_size is too small for a KNF1 payload")
        payload: dict[str, Any] = {"ciphertext_size": ciphertext_size}
        if ttl_hours is not None:
            payload["ttl_hours"] = ttl_hours
        body = self._request("POST", "/api/v1/files", json=payload)
        return FileUpload(
            upload_url=body["upload_url"],
            file_key=body["file_key"],
            upload_headers={str(k): str(v) for k, v in (body.get("upload_headers") or {}).items()},
            upload_expires_in=int(body.get("upload_expires_in") or 0),
        )

    def upload_ciphertext(
        self,
        upload: FileUpload,
        ciphertext: Ciphertext,
        ciphertext_size: int | None = None,
    ) -> None:
        """PUTs KNF1 bytes to the upload URL with exactly the issued headers. The API key is never sent there.

        ``ciphertext`` may be bytes or an iterable of byte chunks (for example ``knf.encrypt_stream(...)``). For an
        iterable, ``ciphertext_size`` is required and must equal the size passed to :meth:`create_file_upload`.
        """
        content: bytes | Iterator[bytes]
        if isinstance(ciphertext, (bytes, bytearray, memoryview)):
            content = bytes(ciphertext)
            if ciphertext_size is not None and ciphertext_size != len(content):
                raise ValueError("ciphertext_size does not match the ciphertext length")
            ciphertext_size = len(content)
        else:
            if ciphertext_size is None:
                raise ValueError("ciphertext_size is required when ciphertext is an iterable")
            content = _checked_stream(ciphertext, ciphertext_size)

        headers = httpx.Headers(upload.upload_headers)
        declared = headers.get("content-length")
        if declared is not None and declared != str(ciphertext_size):
            raise ValueError("upload_headers Content-Length does not match ciphertext_size")
        headers["Content-Length"] = str(ciphertext_size)

        response = self._http.put(upload.upload_url, content=content, headers=headers)
        if not 200 <= response.status_code < 300:
            raise KonfidantApiError(
                f"file upload failed: HTTP {response.status_code}",
                response.status_code,
                response.text,
            )

    def complete_file_upload(self, file_key: str) -> CompletedFileUpload:
        """Finalizes an upload. Raises :class:`KonfidantApiError` (409 ``upload_incomplete``) if no upload landed."""
        body = self._request("POST", f"/api/v1/files/{quote(file_key, safe='')}/complete")
        return CompletedFileUpload(
            download_url=body["download_url"],
            file_id=body.get("file_id"),
            expires_at=body["expires_at"],
            verified_burn=bool(body.get("verified_burn", False)),
        )

    # ------------------------------------------------------------------
    # Recipients
    # ------------------------------------------------------------------

    def open_share(self, share_url: str) -> OpenedShare:
        """Downloads and decrypts a share. Single use: the server deletes the ciphertext once it is fetched.

        The request goes to the link's own origin and never carries the API key. Raises :class:`KonfidantApiError`
        with status 410 if the link was already used or has expired, and :class:`knf.KnfError` if decryption fails.
        """
        parsed = knf.parse_share_url(share_url)
        decryptor = knf.Decryptor(parsed.key)
        with self._http.stream(
            "POST",
            parsed.origin + "/api/download",
            json={"t": parsed.token},
            headers={"Accept": "application/octet-stream"},
        ) as response:
            if not 200 <= response.status_code < 300:
                response.read()
                raise _error_from_response(response)
            for piece in response.iter_bytes():
                decryptor.push(piece)
        decrypted = decryptor.finish()
        return OpenedShare(
            kind=decrypted.kind,
            name=decrypted.name,
            mime=decrypted.mime,
            data=decrypted.data,
            text=decrypted.text if decrypted.kind == "text" else None,
        )

    # ------------------------------------------------------------------
    # Shares
    # ------------------------------------------------------------------

    def list_shares(
        self,
        type: str | None = None,
        status: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
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
                    file_size_bytes=s.get("file_size_bytes"),
                    created_at=s["created_at"],
                    expires_at=s["expires_at"],
                    accessed_at=s.get("accessed_at"),
                    created_by=s.get("created_by"),
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


def _checked_stream(parts: Iterable[bytes], expected: int) -> Iterator[bytes]:
    sent = 0
    for part in parts:
        sent += len(part)
        if sent > expected:
            raise knf.KnfError(f"Ciphertext exceeds the declared size of {expected} bytes")
        yield part
    if sent != expected:
        raise knf.KnfError(f"Ciphertext is {sent} bytes, declared {expected}")
