# Konfidant Python SDK

[![Test](https://github.com/konfidant/sdk-py/actions/workflows/test.yml/badge.svg)](https://github.com/konfidant/sdk-py/actions/workflows/test.yml)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/f4489c7a56e0492ab94abd7470114ef6)](https://app.codacy.com/gh/konfidant/sdk-py/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)
[![Codacy Badge](https://app.codacy.com/project/badge/Coverage/f4489c7a56e0492ab94abd7470114ef6)](https://app.codacy.com/gh/konfidant/sdk-py/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_coverage)

Python SDK for the [Konfidant](https://www.konfidant.app) API. Encrypt and share text messages and files with time-limited, burn-after-reading links.

## Requirements

- Python 3.11+

## Installation

```bash
pip install konfidant
```

## Quick Start

```python
from konfidant import KonfidantClient

client = KonfidantClient(api_key="your-api-key")

result = client.share_text(text="Secret message", ttl_hours=24)

print(result.share_url)
```

## Authentication

All requests require a Bearer API key. Pass it when constructing the client:

```python
client = KonfidantClient(api_key="your-api-key")
```

## Configuration

```python
client = KonfidantClient(
    api_key="your-api-key",
    base_url="https://www.konfidant.app",  # default
    timeout=120.0,                         # seconds; None disables timeout
)
```

## Usage

### Share a Text Message

Encrypts a text message and returns a share link.

```python
result = client.share_text(text="Secret message", ttl_hours=24)

print(result.text_id)       # "9140b841-..."
print(result.share_url)     # "https://download.konfidant.app?t=..."
print(result.expires_at)    # "2026-06-01 00:00:00"
print(result.verified_burn) # True
```

| Parameter  | Type  | Description                        |
|------------|-------|------------------------------------|
| `text`     | `str` | The message to encrypt             |
| `ttl_hours`| `int` | How long the link is valid (hours) |

---

### Share a File (end-to-end convenience)

The simplest way to share a file. Handles the full flow: get a presigned URL, upload the file, poll until encryption
is complete, return the share link.

```python
with open("document.pdf", "rb") as f:
    data = f.read()

result = client.share_and_upload_file(
    data=data,
    size=len(data),
    filename="document.pdf",
    content_type="application/pdf",
    ttl_hours=48,
)

print(result.share_url)     # "https://download.konfidant.app?t=..."
print(result.file_id)       # "681da863-..."
print(result.expires_at)    # "2026-06-01 00:00:00"
print(result.verified_burn) # True
```

| Parameter       | Type               | Default | Description                            |
|-----------------|--------------------|---------|----------------------------------------|
| `data`          | `bytes \| IO[bytes]` | —     | File content                           |
| `size`          | `int`              | —       | File size in bytes                     |
| `filename`      | `str`              | —       | Original filename including extension  |
| `content_type`  | `str`              | —       | MIME type (e.g. `"application/pdf"`)   |
| `ttl_hours`     | `int`              | —       | How long the link is valid (hours)     |
| `poll_interval` | `float`            | `2.0`   | Seconds between status polls           |
| `timeout`       | `float`            | `60.0`  | Max seconds to wait for encryption     |

---

### Share a File (step-by-step)

Use the low-level methods when you need more control — for example, to track upload progress or handle polling
yourself.

**Step 1 — Request a presigned upload URL:**

```python
presigned = client.share_file(
    filename="archive.zip",
    file_size=10_485_760,  # bytes
    ttl_hours=48,
)

print(presigned.upload_url) # short-lived URL
print(presigned.file_key)   # use this to poll status
print(presigned.poll_url)   # convenience poll URL
```

**Step 2 — Upload the file:**

```python
with open("archive.zip", "rb") as f:
    client.upload_file(
        data=f,
        size=10_485_760,
        content_type="application/zip",
        presigned=presigned,
    )
```

**Step 3 — Poll until encryption completes:**

```python
import time

while True:
    status = client.get_file_status(presigned.file_key)
    if status.status == "complete":
        print(status.share_url)
        break
    print(f"Status: {status.message}")
    time.sleep(2)
```

---

### List Shares

Returns all shares for the authenticated organization.

```python
response = client.list_shares()

for share in response.shares:
    print(share.type)            # "file" or "text"
    print(share.file_name)
    print(share.file_size_bytes)
    print(share.created_at)
    print(share.expires_at)
    print(share.accessed_at)     # None if not yet accessed
    print(share.created_by)

print(response.pagination.total)
print(response.pagination.has_more)
```

**Filtering and pagination:**

```python
response = client.list_shares(
    type="file",     # "file" or "text"
    status="active", # "active" or "accessed"
    limit=10,
    offset=20,
)
```

| Parameter | Type            | Description                       |
|-----------|-----------------|-----------------------------------|
| `type`    | `str`, optional | Filter by share type              |
| `status`  | `str`, optional | Filter by access status           |
| `limit`   | `int`, optional | Max results to return             |
| `offset`  | `int`, optional | Number of results to skip         |

---

## Error Handling

All API errors raise `KonfidantApiError`:

```python
from konfidant import KonfidantClient, KonfidantApiError

client = KonfidantClient(api_key="your-api-key")

try:
    result = client.share_text(text="Secret", ttl_hours=24)
except KonfidantApiError as e:
    print(e.status_code)  # e.g. 401
    print(str(e))         # e.g. "Missing or invalid Authorization header."
    print(e.body)         # raw response body (dict or str)
```

`upload_file` raises `KonfidantApiError` if the S3 upload fails. `share_and_upload_file` raises `TimeoutError` if
encryption does not complete within the configured timeout.

## Development

```bash
# Install dependencies
poetry install

# Run tests
poetry run pytest

# Run tests with coverage
poetry run pytest --cov=konfidant
```
