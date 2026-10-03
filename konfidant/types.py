from dataclasses import dataclass, field
from typing import Literal


@dataclass(frozen=True)
class ShareTextResult:
    share_url: str
    """Link to send to the recipient. Carries the single-use token and the decryption key in its fragment."""
    text_id: str | None
    expires_at: str


@dataclass(frozen=True)
class FileUpload:
    upload_url: str
    file_key: str
    upload_headers: dict[str, str] = field(default_factory=dict)
    upload_expires_in: int = 0


@dataclass(frozen=True)
class CompletedFileUpload:
    download_url: str
    """Server-issued link carrying only ``#t=<token>``. Append the key with ``knf.build_share_url``."""
    file_id: str | None
    expires_at: str
    verified_burn: bool


@dataclass(frozen=True)
class ShareFileResult:
    share_url: str
    """Link to send to the recipient. Carries the single-use token and the decryption key in its fragment."""
    file_id: str | None
    expires_at: str
    verified_burn: bool


@dataclass(frozen=True)
class OpenedShare:
    kind: Literal["text", "file"]
    name: str
    """Original file name (empty for text shares)."""
    mime: str
    """MIME type (empty for text shares; may be empty for files)."""
    data: bytes
    text: str | None
    """Decoded text for text shares, ``None`` for file shares."""


@dataclass(frozen=True)
class Share:
    type: str
    file_size_bytes: int | None
    created_at: str
    expires_at: str
    accessed_at: str | None
    created_by: str | None


@dataclass(frozen=True)
class Pagination:
    total: int
    limit: int
    offset: int
    has_more: bool


@dataclass(frozen=True)
class ListSharesResponse:
    shares: list[Share]
    pagination: Pagination
