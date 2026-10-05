# Konfidant Python SDK

[![Test](https://github.com/konfidant/sdk-py/actions/workflows/test.yml/badge.svg)](https://github.com/konfidant/sdk-py/actions/workflows/test.yml)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/f4489c7a56e0492ab94abd7470114ef6)](https://app.codacy.com/gh/konfidant/sdk-py/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)
[![Codacy Badge](https://app.codacy.com/project/badge/Coverage/f4489c7a56e0492ab94abd7470114ef6)](https://app.codacy.com/gh/konfidant/sdk-py/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_coverage)

Python SDK for the [Konfidant](https://www.konfidant.app?utm_source=github&utm_medium=pythonsdk&utm_campaign=github) API. Share text and files through single-use,
time-limited links that are **encrypted on your machine** before anything is sent.

## Zero-knowledge model

- Every share gets a fresh random 256-bit key. Content is encrypted locally with AES-256-GCM in the
  KNF1 format (chunked, authenticated, truncation-resistant).
- Konfidant receives **only ciphertext**. The file name and MIME type are encrypted too; the server learns only the
  ciphertext size and when the share was created and opened.
- The key lives **only in the share link's URL fragment**:

  ```
  https://download.konfidant.app/#t=<single-use token>&k=<key>
  ```

  Browsers and HTTP clients never send the fragment to a server. The `t` token lets the recipient fetch the
  ciphertext exactly once; the `k` key decrypts it locally.
- Treat the share URL as the secret. Do not log it, and send it to the recipient over a channel you trust. If the
  link is lost, the content cannot be recovered: Konfidant does not have the key.

## Requirements

- Python 3.11+
- [`httpx`](https://www.python-httpx.org/) and [`cryptography`](https://cryptography.io/) (installed automatically)

## Installation

```bash
pip install konfidant
```

## Quick start

```python
from konfidant import KonfidantClient

with KonfidantClient(api_key="your-api-key") as client:
    result = client.share_text("Secret message", ttl_hours=24)
    print(result.share_url)  # https://download.konfidant.app/#t=...&k=...
```

## Configuration

```python
client = KonfidantClient(
    api_key="your-api-key",                # sent as "Authorization: Bearer <api_key>" to the Konfidant API only
    base_url="https://www.konfidant.app",  # default
    timeout=120.0,                         # seconds; None disables the timeout
)
```

## Usage

### Share text

```python
result = client.share_text("Secret message", ttl_hours=24)

result.share_url   # "https://download.konfidant.app/#t=...&k=..."
result.text_id     # "9140b841-..." or None
result.expires_at  # "2026-10-04T12:00:00.000Z"
```

| Parameter   | Type          | Description                                                   |
|-------------|---------------|---------------------------------------------------------------|
| `text`      | `str`         | The message. Encrypted locally; never sent in plaintext.      |
| `ttl_hours` | `int \| None` | How long the link stays valid. `None` uses the server default. |

### Share a file

Encrypts locally, uploads the ciphertext and returns the share link in one call.

```python
with open("report.pdf", "rb") as f:
    result = client.share_file(f, filename="report.pdf", content_type="application/pdf", ttl_hours=48)

result.share_url      # "https://download.konfidant.app/#t=...&k=..."
result.file_id        # "681da863-..." or None
result.expires_at     # "2026-10-05T12:00:00.000Z"
result.verified_burn  # True when the organization records burn-on-read confirmation
```

| Parameter      | Type                    | Default | Description                                                        |
|----------------|-------------------------|---------|--------------------------------------------------------------------|
| `data`         | `bytes \| BinaryIO`     | —       | Content, or a binary file object (read from its current position) |
| `filename`     | `str`                   | —       | Original file name, at most 1024 UTF-8 bytes. Encrypted.           |
| `content_type` | `str`                   | `""`    | MIME type, at most 255 bytes. Encrypted.                           |
| `ttl_hours`    | `int \| None`           | `None`  | How long the link stays valid. `None` uses the server default.     |

Seekable files are encrypted and uploaded chunk by chunk (a few MB of memory at a time). Non-seekable streams
(pipes, sockets) are read into memory first, because the exact ciphertext size must be declared before the upload.
Files larger than your plan's limit are rejected by the API before anything is uploaded.

### Share a file step by step

The low-level methods expose each stage, for example to run the upload yourself. Encryption comes from the
`konfidant.knf` module.

```python
from konfidant import knf

content = open("archive.zip", "rb").read()
key = knf.generate_key()
ciphertext = knf.encrypt(key, content, kind="file", name="archive.zip", mime="application/zip")

upload = client.create_file_upload(ciphertext_size=len(ciphertext), ttl_hours=48)
client.upload_ciphertext(upload, ciphertext)          # PUT with exactly upload.upload_headers, no API key
completed = client.complete_file_upload(upload.file_key)

share_url = knf.build_share_url(completed.download_url, key)  # appends "&k=<key>" to "#t=<token>"
```

- `create_file_upload(ciphertext_size, ttl_hours=None)` returns `upload_url`, `file_key`, `upload_headers` and
  `upload_expires_in` (seconds). `ciphertext_size` must be the exact KNF1 length; compute it up front with
  `knf.ciphertext_size(len(knf.encode_metadata("file", name, mime)), content_length)`.
- `upload_ciphertext(upload, ciphertext, ciphertext_size=None)` accepts bytes or an iterable of byte chunks such as
  `knf.encrypt_stream(...)` (then `ciphertext_size` is required). The API key is never sent to the upload URL.
- `complete_file_upload(file_key)` returns `download_url`, `file_id`, `expires_at` and `verified_burn`. It raises
  `KonfidantApiError` with status `409` (`upload_incomplete`) if the upload has not landed.

### Open a share (recipient side)

```python
opened = client.open_share("https://download.konfidant.app/#t=...&k=...")

opened.kind  # "text" or "file"
opened.text  # decoded text for text shares, None for files
opened.name  # original file name ("" for text)
opened.mime  # MIME type ("" for text, may be "" for files)
opened.data  # decrypted bytes
```

`open_share` posts the token to the link's own origin (`download.konfidant.app` or a custom domain) and decrypts the
response locally. It never sends the API key or the decryption key. Links are **single use**: the ciphertext is deleted
once fetched, and a second attempt raises `KonfidantApiError` with status `410`.

### List shares

```python
response = client.list_shares(type="file", status="active", limit=10, offset=0)

for share in response.shares:
    share.type             # "file" or "text"
    share.file_size_bytes  # may be None
    share.created_at
    share.expires_at
    share.accessed_at      # None if not yet opened
    share.created_by       # creator's email, None if the user was deleted

response.pagination.total
response.pagination.has_more
```

File names are not listed: the server never sees them.

## Encryption module

`konfidant.knf` implements KNF1 and can be used without the client:

| Function                                                             | Description                                         |
|----------------------------------------------------------------------|-----------------------------------------------------|
| `generate_key()`                                                     | 32 random bytes                                     |
| `encode_key(key)` / `decode_key(s)`                                  | Unpadded base64url, 43 characters                   |
| `encrypt(key, source, kind=, name=, mime=)`                          | Bytes or binary file object → KNF1 bytes            |
| `encrypt_stream(...)`                                                | Same, yields header and sealed chunks lazily        |
| `encrypt_text(key, text)`                                            | Text share payload                                  |
| `decrypt(key, ciphertext)`                                           | → `KnfDecrypted(kind, name, mime, data, .text)`     |
| `Decryptor(key).push(bytes)` / `.finish()`                           | Incremental decryption of streamed downloads        |
| `ciphertext_size(meta_len, content_len)`                             | Exact KNF1 size                                     |
| `build_share_url(download_url, key)` / `parse_share_url(url)`        | Share link helpers                                  |

Any authentication failure (wrong key, modified, reordered or truncated data) raises `knf.KnfError` and returns no
plaintext.

## Error handling

```python
from konfidant import KonfidantApiError, KnfError, KonfidantClient

try:
    result = client.share_text("Secret", ttl_hours=24)
except KonfidantApiError as e:
    e.status_code  # e.g. 401, 409, 410
    str(e)         # the API's "error" code, e.g. "unauthorized"
    e.body         # parsed JSON {"error": ..., "message": ...} or raw text
except KnfError as e:
    ...            # invalid input (e.g. file name too long) or failed decryption
```

`upload_ciphertext` raises `KonfidantApiError` if the storage upload fails.

## Development

```bash
poetry install --with dev
poetry run pytest --cov=konfidant
```

`tests/knf1-test-vectors.json` holds the KNF1 test vectors shared with the web app; the tests reproduce every
ciphertext byte for byte.
