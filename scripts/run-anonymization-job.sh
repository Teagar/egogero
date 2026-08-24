#!/bin/sh
set -u

max_attempts="${ANONYMIZATION_MAX_ATTEMPTS:-3}"
timeout_seconds="${ANONYMIZATION_TIMEOUT_SECONDS:-1800}"
delay_seconds="${ANONYMIZATION_RETRY_DELAY_SECONDS:-30}"
attempt=1

while [ "$attempt" -le "$max_attempts" ]; do
  if timeout "$timeout_seconds" npm run privacy:anonymize; then
    exit 0
  fi

  if [ "$attempt" -lt "$max_attempts" ]; then
    sleep "$delay_seconds"
    delay_seconds=$((delay_seconds * 2))
  fi
  attempt=$((attempt + 1))
done

echo "Guest anonymization failed after ${max_attempts} attempts" >&2
exit 1
