from dataclasses import dataclass
from typing import Optional


@dataclass
class FileMetadataHeaders:
    user_id: str
    ttl_hours: str
    organization_id: str


@dataclass
class ShareTextResponse:
    text_id: str
    share_url: str
    expires_at: str
    verified_burn: bool


@dataclass
class ShareFileResponse:
    upload_url: str
    file_key: str
    metadata_headers: FileMetadataHeaders
    poll_url: str


@dataclass
class FileStatusResponse:
    status: str  # "processing" or "complete"
    message: Optional[str] = None
    file_id: Optional[str] = None
    file_name: Optional[str] = None
    share_url: Optional[str] = None
    expires_at: Optional[str] = None
    verified_burn: Optional[bool] = None


@dataclass
class Share:
    type: str
    file_name: str
    file_size_bytes: int
    created_at: str
    expires_at: str
    accessed_at: Optional[str]
    created_by: str


@dataclass
class Pagination:
    total: int
    limit: int
    offset: int
    has_more: bool


@dataclass
class ListSharesResponse:
    shares: list[Share]
    pagination: Pagination


@dataclass
class ShareResult:
    share_url: str
    file_id: str
    expires_at: str
    verified_burn: bool
