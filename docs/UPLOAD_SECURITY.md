# Upload Security (POST /api/upload)

Controls for Cloudinary uploads after ISSUE-SAL-001.

## Authentication

- **Required:** `Authorization: Bearer <token>`
- Accepted principals:
  - User / therapist Redis session (`ValidateSession`)
  - Admin Redis session (`ValidateAdminSession`)
  - Therapist JWT (`ValidateAccessToken`)
  - Receptionist JWT (`ValidateReceptionistAccessToken`)
- Unauthenticated requests → **401** `{ "success": false, "message": "Authentication required" }`

## CORS

- Handlers **must not** set `Access-Control-Allow-Origin`.
- Browser access uses the global allowlist in `middleware.CORS` (`ALLOWED_ORIGINS` / frontend URL env vars).
- Responses never use `Access-Control-Allow-Origin: *`.

## Size limit

- Multipart parse cap: **10MB** (`ParseMultipartForm(10 << 20)`).
- Oversized / invalid bodies → **400** with a generic message (no raw parse errors).

## Per-user daily quota

| Setting | Value |
|--------|--------|
| Limit | **20 uploads / principal / UTC day** (`services.UploadQuotaPerDay`) |
| Store | Redis |
| Key | `upload_quota:{principalID}:{YYYY-MM-DD}` (UTC) |
| TTL | Until next UTC midnight |
| Exceeded | **429** `"Daily upload quota exceeded. Try again tomorrow."` |
| Redis down | **503** (fail closed — prevents unbounded Cloudinary spend) |

Response headers on accepted / quota-rejected requests:

- `X-Upload-Quota-Limit`
- `X-Upload-Quota-Remaining`

Quota is consumed when the request is authorized and the quota check succeeds (before Cloudinary I/O). Failed Cloudinary uploads still count against the daily allotment to discourage retry storms; revisit if product needs otherwise.

## Related issues

- ISSUE-SAL-002 — MIME / magic-byte validation
- ISSUE-SAL-003 — restrict `?folder=`
- ISSUE-SAL-045 — global MaxBytes for JSON bodies
- ISSUE-SAL-046 — no raw `err.Error()` to clients

See also: [SAL Remediation Checklist](../../docs/SAL_REMEDIATION_CHECKLIST.md), [Rate Limiting](./RATE_LIMITING.md).
