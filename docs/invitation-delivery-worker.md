# Invitation delivery worker

Run `npm run delivery:worker` independently from the HTTP server after applying migrations. The worker uses `IDEMPOTENCY_CACHE_SECRET` to decrypt PC-19 payloads immediately before provider I/O. A mismatched key fails before any intent is claimed.

Claims are bounded and use `FOR UPDATE SKIP LOCKED`. The claim transaction records `processing`, an owner, a unique fencing token, and lease expiry, then commits before calling a provider. Lease renewal starts immediately for every claimed row, including rows waiting for a concurrency slot, without retaining the claim transaction. Success and failure updates require the same owner and fencing token; row locking linearizes finalization against a competing reclaim. A crash does not consume an attempt before an observable provider outcome, so expired claims remain recoverable. Every provider adapter must durably honor `DeliveryIntent.id` as its idempotency key because a process can stop after provider acceptance but before database finalization.

The built-in no-op provider is selected only when `NODE_ENV=development`. Production, staging, missing, and misspelled environments deliberately use an unavailable provider until a commercial adapter with durable idempotency is injected; those attempts enter retry rather than pretending to deliver.

Configuration:

- `DELIVERY_BATCH_SIZE`: 1-100, default 50.
- `DELIVERY_CONCURRENCY`: 1-100 and no greater than the batch, default 5.
- `DELIVERY_LEASE_MS`: 1000-3600000, default 60000.
- `DELIVERY_POLL_MS`: 50-60000, default 1000.
- `DELIVERY_MAX_ATTEMPTS`: 1-100, default 8.
- `DELIVERY_PROVIDER_TIMEOUT_MS`: 1000-300000, default 30000. The adapter receives an `AbortSignal` and must stop I/O when aborted.
- `DELIVERY_BASE_BACKOFF_MS`: 100-3600000, default 1000.
- `DELIVERY_MAX_BACKOFF_MS`: 100-86400000 and no less than the base, default 300000.
- `DELIVERY_WORKER_ID`: optional replica identity containing only letters, digits, `.`, `_`, `:`, and `-`.

Each batch emits one `delivery_batch` JSON event with counts by channel and outcome plus duration. Logs never contain intent, invitation, tenant, recipient, payload, token, ciphertext, nonce, authentication tag, or provider error text. `lastError` stores only a fixed low-cardinality error code. `SIGINT` and `SIGTERM` stop new claims, abort provider I/O, leave unfinished rows recoverable after lease expiry, and disconnect cleanly.

The first worker persists a fingerprint of `DELIVERY_MAX_ATTEMPTS`; replicas configured with another value fail before claiming. Change this policy only through an explicit coordinated operation after all old replicas stop.
