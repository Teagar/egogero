# Invitation idempotency and delivery outbox

Both invitation creation endpoints require an `Idempotency-Key` containing 16 to 128 ASCII letters, digits, `.`, `_`, `:`, or `-`. A key is scoped by authenticated actor, condominium, HTTP method, and route template. Object keys in the request body are sorted by locale-independent UTF-16 code-unit order before SHA-256 hashing; array order remains significant. Creation payloads are closed schemas, so unknown keys and non-boolean representation flags are rejected before hashing.

The database transaction claims the scoped key through `IdempotencyRecord_scope_key`, creates every invitation, stores one encrypted delivery intent per invitation/channel, and encrypts the exact HTTP 201 JSON response before commit. A concurrent loser waits on PostgreSQL's unique index. It replays after the winner commits or proceeds as the new writer if the winner rolls back. Reusing a live key with a different request hash returns HTTP 409.

`IDEMPOTENCY_CACHE_SECRET` must contain at least 32 bytes and is independent from `INVITATION_TOKEN_SECRET`. AES-256-GCM protects replay and outbox payloads with record-specific authenticated data. Version 1 derives the 32-byte AES key as `SHA-256(UTF-8 secret)` and uses a random 12-byte IV plus a 16-byte authentication tag. Only version `1`, IVs, authentication tags, ciphertext, and a one-way secret fingerprint are stored. Startup and operations fail closed when the configured fingerprint differs. Tokens, recipients, subjects, and message bodies are never stored in plaintext in idempotency or outbox rows.

## Outbox consumer contract

`DeliveryIntent.id` is the stable provider idempotency identity. A consumer selects pending rows (`deliveredAt IS NULL`) in `(createdAt, id)` order with `FOR UPDATE SKIP LOCKED`, decrypts with the recorded `keyVersion` and authenticated data `delivery:<intentId>:<invitationId>:<channel>:v<version>`, sends to the recorded channel, and records `deliveredAt` only after provider confirmation. Consumers must use the intent ID as the provider idempotency key so a crash after provider acceptance remains safe, and must not derive identity from ciphertext. Worker claiming, retries, and failure policy are intentionally outside PC-19.

Request handlers never call a provider. HTTP 201 means invitation issuance and durable enqueue both committed. Replays only decrypt the stored response.

## Replay cleanup

`IDEMPOTENCY_REPLAY_TTL_SECONDS` defaults to 86400 (24 hours) and accepts 60 through 2592000 seconds. Expiry is calculated immediately before transaction commit. Run `npm run idempotency:cleanup` at least hourly. `IDEMPOTENCY_CLEANUP_BATCH_SIZE` defaults to 500 and accepts 1 through 10000.

Each invocation removes one ordered page using `FOR UPDATE SKIP LOCKED`, rechecks confirmation and expiry during deletion, and emits one JSON metric containing `deleted`, `batchSize`, `durationMs`, and `hasMore`. Schedule another invocation while `hasMore` is true. Cleanup removes only confirmed replay rows and encrypted response blobs; delivery intents have no idempotency-record foreign key and remain untouched. After cleanup, the same key starts a new operation. Small batches reduce lock pressure; sustained `hasMore: true` means frequency or batch size should be increased.
