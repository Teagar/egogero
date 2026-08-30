import { pathToFileURL } from 'node:url';

import {
  createAuthAlertWebhookAdapter,
  DEFAULT_AUTH_ALERT_ROUTES,
  type AuthAlertDeliveryAdapter,
  type AuthAlertType
} from './auth-observability.js';

export const AUTH_ALERT_SMOKE_CONTRACT = 'egogero.auth-alert-smoke/v1' as const;

export async function runAuthAlertSmoke(adapter: AuthAlertDeliveryAdapter, timeoutMs = 5_000) {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 10_000) {
    throw new Error('Alert smoke timeout must be an integer between 100 and 10000');
  }
  const types = Object.keys(DEFAULT_AUTH_ALERT_ROUTES) as AuthAlertType[];
  for (const type of types) {
    const controller = new AbortController();
    let rejectTimeout: (error: Error) => void = () => {};
    const timeout = new Promise<never>((_, reject) => { rejectTimeout = reject; });
    let cancel: (() => void) | undefined;
    const timer = setTimeout(() => {
      controller.abort();
      try { cancel?.(); } catch { /* cancellation is best effort */ }
      rejectTimeout(new Error(`Alert smoke timed out for ${type}`));
    }, timeoutMs);
    try {
      const result = adapter({
        contract: 'egogero.auth-alert-delivery/v1', type, routes: DEFAULT_AUTH_ALERT_ROUTES[type]
      }, controller.signal);
      const operation = result instanceof Promise ? { promise: result } : result;
      cancel = operation.cancel;
      const acknowledgement = await Promise.race([operation.promise, timeout]);
      if (acknowledgement?.acknowledged !== true) throw new Error(`Alert smoke was not acknowledged for ${type}`);
    } finally {
      clearTimeout(timer);
    }
  }
  return { contract: AUTH_ALERT_SMOKE_CONTRACT, acknowledged: true as const, alertTypes: types.length };
}

async function main() {
  const args = process.argv.slice(2);
  const urlIndex = args.indexOf('--url');
  const timeoutIndex = args.indexOf('--timeout-ms');
  const url = urlIndex >= 0 ? args[urlIndex + 1] : undefined;
  const timeoutMs = timeoutIndex >= 0 ? Number(args[timeoutIndex + 1]) : 5_000;
  if (!url) throw new Error('Usage: auth:alerts:smoke -- --url https://alerts.example/path [--timeout-ms 5000]');
  const result = await runAuthAlertSmoke(createAuthAlertWebhookAdapter(url), timeoutMs);
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(() => {
    process.stderr.write('Alert smoke failed\n');
    process.exitCode = 2;
  });
}
