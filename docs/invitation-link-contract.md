# Invitation Link and QR Contract

Link and QR output is opt-in on invitation issuance. Add `link: true` and/or
`qrCode: true` to the single invitation request, or to the batch request. QR
output implies `link` output so the decoded payload can be inspected.

The response contains the existing six-digit `token`, plus `link` when
requested and `qrCode` when requested. `qrCode` is a standard PNG data URL
(`data:image/png;base64,...`) and decodes to the exact `link` string.

The link has this form:

`https://public.example/portaria/convites/validar#token=123456`

The scanner/client MUST read the fragment locally, remove it from any network
request, obtain the access type from the gatehouse workflow, and POST
`{ "token": "123456", "tipoAcesso": "pedestre" }` (or `veiculo`) to
`/portaria/convites/validar` using the existing portaria authentication. A GET
to the link is not a validation operation and must not be implemented as one.
The fragment prevents bearer-token disclosure through HTTP request and access
logs. The validation endpoint owns tenant, expiration, revocation, replay, and
single-use semantics.

Set `PUBLIC_VALIDATION_BASE_URL` to an absolute HTTPS URL without credentials,
query, or fragment. Link/QR requests fail closed with `503` when it is absent
or unsafe. No link or QR value is persisted or logged; issuance responses are
`Cache-Control: no-store`.
