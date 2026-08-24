# Guest Data Retention

Run `npm run privacy:anonymize` from the built application image on a scheduler.
The default retention period is 12 calendar months and each transaction handles
up to 500 guests. Configure these values with:

- `ANONYMIZATION_RETENTION_MONTHS`: integer from 1 to 120.
- `ANONYMIZATION_BATCH_SIZE`: integer from 1 to 1000.

The job anonymizes a guest only when every invitation with that guest ID has a
known expiration at or before the cutoff. A recent invitation or a legacy
invitation without an expiration blocks anonymization. Soft-deleted guests and
invitations remain subject to retention because deletion does not erase personal
data. A guest registration that never received an invitation is anonymized when
its own creation timestamp reaches the same cutoff.

The guest name becomes `Convidado anonimizado`; e-mail and telephone become
null. Duplicated guest names in entry notifications are also replaced. IDs,
invitation history, timestamps, and immutable access audits are preserved. The
job is idempotent, processes locked batches with `SKIP LOCKED`, and emits only a
count and cutoff, never guest identifiers or personal data.

An anonymized guest ID is historical and cannot be edited or receive another
invitation. Registering that person again creates a new guest ID, preventing new
PII from being linked back to old immutable audit entries.

## Scheduling Contract

Run the Compose job once per day after migrations, for example at `03:00 UTC`:

```cron
0 3 * * * cd /srv/egogero && flock -n /run/egogero-anonymize.lock docker compose run --rm anonymize
```

Only one job may run at a time. The image wrapper enforces a 30-minute timeout
and three attempts with exponential backoff. A nonzero final exit must be wired
to the scheduler's failure alert. A skipped lock therefore cannot be reported
as a successful complete run; the daily cadence is the maximum retention delay
after transient application activity.
