export type AuthMetricName =
  | 'auth_oidc_callback_total'
  | 'auth_session_lookup_seconds'
  | 'auth_session_database_seconds'
  | 'auth_session_lookup_total'
  | 'auth_session_revocation_seconds'
  | 'auth_database_writes_total'
  | 'auth_rate_limit_decisions_total';

export type AuthMetricLabels = Readonly<Record<string, string>>;

export interface AuthMetrics {
  increment(name: AuthMetricName, labels: AuthMetricLabels, value?: number): void | Promise<void>;
  observe(name: AuthMetricName, value: number, labels: AuthMetricLabels): void | Promise<void>;
}

export type AuthAlertType =
  | 'rate_limit_repeated_excess'
  | 'crypto_integrity_failure'
  | 'crypto_key_failure'
  | 'oidc_replay_or_state_miss'
  | 'oidc_issuer_mixup'
  | 'oidc_callback_success_slo'
  | 'session_lookup_latency_slo';

export interface AuthAlertSink {
  emit(type: AuthAlertType, details: Readonly<Record<string, unknown>>): void | Promise<void>;
}

export const noopAuthMetrics: AuthMetrics = {
  increment() {},
  observe() {}
};

export const noopAuthAlerts: AuthAlertSink = { emit() {} };

const SENSITIVE_KEY = /(?:authorization|cookie|token|secret|code|credential|digest|ciphertext|nonce|auth.?tag|api.?key|pkce|csrf|invitation|device)/i;

export function redactAuthData(value: unknown, seen = new WeakSet<object>()): unknown {
  if (value === null || typeof value === 'boolean' || typeof value === 'number') return value;
  if (typeof value === 'string') {
    if (/\b(?:Bearer|Basic)\s+\S+/i.test(value)
      || /\begdev_[A-Za-z0-9_-]+\b/.test(value)
      || /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/.test(value)
      || /^[A-Za-z0-9_-]{43}$/.test(value)) return '[redacted]';
    return value.length > 512 ? `${value.slice(0, 512)}[truncated]` : value;
  }
  if (typeof value !== 'object') return '[redacted]';
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return '[redacted]';
  if (seen.has(value)) return '[circular]';
  seen.add(value);
  if (Array.isArray(value)) return value.slice(0, 50).map((entry) => redactAuthData(entry, seen));

  const redacted: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(value).slice(0, 50)) {
    redacted[key] = SENSITIVE_KEY.test(key) ? '[redacted]' : redactAuthData(entry, seen);
  }
  return redacted;
}

export function safeAuthMetrics(sink: AuthMetrics = noopAuthMetrics): AuthMetrics {
  return {
    increment(name, labels, value) {
      try { void Promise.resolve(sink.increment(name, labels, value)).catch(() => {}); } catch { /* telemetry is non-authoritative */ }
    },
    observe(name, value, labels) {
      try { void Promise.resolve(sink.observe(name, value, labels)).catch(() => {}); } catch { /* telemetry is non-authoritative */ }
    }
  };
}

export function safeAuthAlerts(sink: AuthAlertSink = noopAuthAlerts): AuthAlertSink {
  return {
    emit(type, details) {
      try { void Promise.resolve(sink.emit(type, redactAuthData(details) as Record<string, unknown>)).catch(() => {}); } catch { /* alerts cannot change auth decisions */ }
    }
  };
}

export type AuthAggregateSnapshot = {
  callbackSuccess: number;
  callbackFailure: number;
  sessionLookupSeconds: readonly number[];
};

export function evaluateAuthAggregates(snapshot: AuthAggregateSnapshot, sink: AuthAlertSink = noopAuthAlerts) {
  const alerts = safeAuthAlerts(sink);
  const callbacks = snapshot.callbackSuccess + snapshot.callbackFailure;
  if (callbacks >= 100 && snapshot.callbackSuccess / callbacks < 0.995) {
    alerts.emit('oidc_callback_success_slo', { outcome: 'below_threshold', thresholdPermille: 995 });
  }
  if (snapshot.sessionLookupSeconds.length >= 100) {
    const ordered = [...snapshot.sessionLookupSeconds].sort((left, right) => left - right);
    const p95 = ordered[Math.ceil(ordered.length * 0.95) - 1] ?? 0;
    if (p95 > 0.020) alerts.emit('session_lookup_latency_slo', { outcome: 'above_threshold', thresholdMs: 20 });
  }
}

export function createAuthTestCollectors() {
  const metrics: Array<{ name: AuthMetricName; value: number; labels: AuthMetricLabels; kind: 'counter' | 'histogram' }> = [];
  const alerts: Array<{ type: AuthAlertType; details: Readonly<Record<string, unknown>> }> = [];
  return {
    metrics,
    alerts,
    metricSink: {
      increment(name: AuthMetricName, labels: AuthMetricLabels, value = 1) { metrics.push({ name, labels, value, kind: 'counter' }); },
      observe(name: AuthMetricName, value: number, labels: AuthMetricLabels) { metrics.push({ name, labels, value, kind: 'histogram' }); }
    } satisfies AuthMetrics,
    alertSink: {
      emit(type: AuthAlertType, details: Readonly<Record<string, unknown>>) { alerts.push({ type, details }); }
    } satisfies AuthAlertSink
  };
}
