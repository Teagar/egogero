import { randomUUID } from 'node:crypto';
import { appendFile } from 'node:fs/promises';
import type { FastifyInstance } from 'fastify';

import {
  AUTH_ROLLOUT_CONTRACT,
  AUTH_SESSION_HISTOGRAM_BOUNDS_SECONDS,
  type AuthRolloutCounter,
  type AuthRolloutHistogram,
  type AuthRolloutSnapshot
} from './auth-rollout.js';

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

export type AuthSnapshotSink = (snapshot: AuthRolloutSnapshot) => void | Promise<void>;

export type StructuredAuthTelemetry = {
  metrics: AuthMetrics;
  alerts: AuthAlertSink;
  flush(): AuthRolloutSnapshot | undefined;
};

const CRITICAL_ALERTS = new Set<AuthAlertType>([
  'crypto_integrity_failure', 'crypto_key_failure', 'oidc_replay_or_state_miss', 'oidc_issuer_mixup'
]);
const DIMENSIONS: Record<AuthMetricName, Readonly<Record<string, readonly string[]>>> = {
  auth_oidc_callback_total: { outcome: ['success', 'failure'], reason: ['none', 'state', 'issuer', 'crypto', 'account', 'validation'] },
  auth_session_lookup_seconds: { operation: ['authenticate', 'inspect'], outcome: ['hit', 'miss', 'failure'] },
  auth_session_database_seconds: { operation: ['authenticate', 'inspect'], outcome: ['hit', 'miss', 'failure'] },
  auth_session_lookup_total: { operation: ['authenticate', 'inspect'], outcome: ['hit', 'miss', 'failure'] },
  auth_session_revocation_seconds: { operation: ['current'], outcome: ['revoked', 'already-revoked', 'unavailable'] },
  auth_database_writes_total: { operation: ['recovery', 'session_issue', 'session_rotate', 'session_revoke'], outcome: ['success', 'failure'] },
  auth_rate_limit_decisions_total: {
    operation: ['login_ip', 'callback_failure_ip', 'session_issue_account', 'recovery_ip', 'reauthentication_account', 'authentication_failure_ip'],
    outcome: ['allowed', 'denied']
  }
};

function boundedDimensions(name: AuthMetricName, labels: AuthMetricLabels) {
  return Object.fromEntries(Object.entries(DIMENSIONS[name]).map(([key, allowed]) => [
    key, allowed.includes(labels[key]) ? labels[key] : 'other'
  ]));
}

function aggregateKey(name: AuthMetricName, dimensions: Readonly<Record<string, string>>) {
  return `${name}:${Object.entries(dimensions).map(([key, value]) => `${key}=${value}`).join(',')}`;
}

export function createAuthSnapshotStdoutSink(stream: NodeJS.WriteStream = process.stdout): AuthSnapshotSink {
  return (snapshot) => {
    if (stream.write(`${JSON.stringify(snapshot)}\n`)) return;
    return new Promise<void>((resolve) => stream.once('drain', resolve));
  };
}

export function createAuthSnapshotFileSink(path: string): AuthSnapshotSink {
  let writes = Promise.resolve();
  return (snapshot) => {
    writes = writes.then(() => appendFile(path, `${JSON.stringify(snapshot)}\n`, { encoding: 'utf8', mode: 0o600 }));
    return writes;
  };
}

export function createStructuredAuthTelemetry(
  sink: AuthSnapshotSink = createAuthSnapshotStdoutSink(),
  options: { instanceId?: string; now?: () => number; sinkTimeoutMs?: number } = {}
): StructuredAuthTelemetry {
  const instanceId = options.instanceId ?? randomUUID();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(instanceId)) {
    throw new Error('Auth telemetry instanceId must be a non-sensitive UUID v4');
  }
  const now = options.now ?? Date.now;
  const sinkTimeoutMs = options.sinkTimeoutMs ?? 5_000;
  const counters = new Map<string, AuthRolloutCounter>();
  const histograms = new Map<string, { metric: AuthMetricName; dimensions: Record<string, string>; bucketCounts: number[]; count: number }>();
  const alertCounts = new Map<AuthAlertType, number>();
  const gaps = new Map<AuthRolloutSnapshot['observability']['gaps'][number]['code'], number>();
  let callbackSuccess = 0;
  let callbackFailure = 0;
  let intervalStart = now();
  let sequence = 0;
  let inFlight = false;
  function markGap(code: AuthRolloutSnapshot['observability']['gaps'][number]['code']) {
    const count = gaps.get(code) ?? 0;
    gaps.set(code, count === Number.MAX_SAFE_INTEGER ? count : count + 1);
  }
  function addBounded(left: number, right: number) {
    if (right > Number.MAX_SAFE_INTEGER - left) {
      markGap('numeric_saturation');
      return Number.MAX_SAFE_INTEGER;
    }
    return left + right;
  }

  const alerts: AuthAlertSink = {
    emit(type) {
      alertCounts.set(type, addBounded(alertCounts.get(type) ?? 0, 1));
    }
  };
  const metrics: AuthMetrics = {
    increment(name, labels, value = 1) {
      if (!Number.isSafeInteger(value) || value < 0) return;
      const dimensions = boundedDimensions(name, labels);
      const key = aggregateKey(name, dimensions);
      const previous = counters.get(key);
      counters.set(key, {
        metric: name,
        dimensions,
        value: addBounded(previous?.value ?? 0, value)
      });
      if (name === 'auth_oidc_callback_total') {
        if (labels.outcome === 'success') callbackSuccess = addBounded(callbackSuccess, value);
        if (labels.outcome === 'failure') callbackFailure = addBounded(callbackFailure, value);
      }
    },
    observe(name, value, labels) {
      if (!Number.isFinite(value) || value < 0) return;
      const dimensions = boundedDimensions(name, labels);
      const key = aggregateKey(name, dimensions);
      const histogram = histograms.get(key) ?? {
        metric: name, dimensions, bucketCounts: Array(AUTH_SESSION_HISTOGRAM_BOUNDS_SECONDS.length + 1).fill(0), count: 0
      };
      const bucket = AUTH_SESSION_HISTOGRAM_BOUNDS_SECONDS.findIndex((bound) => value <= bound);
      const bucketIndex = bucket < 0 ? AUTH_SESSION_HISTOGRAM_BOUNDS_SECONDS.length : bucket;
      histogram.bucketCounts[bucketIndex] = addBounded(histogram.bucketCounts[bucketIndex], 1);
      histogram.count = addBounded(histogram.count, 1);
      histograms.set(key, histogram);
    }
  };

  return {
    metrics,
    alerts,
    flush() {
      const observedEnd = now();
      if (!Number.isFinite(observedEnd) || observedEnd <= intervalStart) markGap('clock_anomaly');
      const end = Number.isFinite(observedEnd) && observedEnd > intervalStart ? observedEnd : intervalStart + 1;
      const sessionBuckets = Array(AUTH_SESSION_HISTOGRAM_BOUNDS_SECONDS.length + 1).fill(0) as number[];
      let sessionCount = 0;
      for (const histogram of histograms.values()) {
        if (histogram.metric !== 'auth_session_lookup_seconds') continue;
        for (let index = 0; index < histogram.bucketCounts.length; index += 1) {
          sessionBuckets[index] = addBounded(sessionBuckets[index], histogram.bucketCounts[index]);
          sessionCount = addBounded(sessionCount, histogram.bucketCounts[index]);
        }
      }
      const callbacks = BigInt(callbackSuccess) + BigInt(callbackFailure);
      if (callbacks >= 100n && BigInt(callbackSuccess) * 1_000n < callbacks * 995n) {
        alerts.emit('oidc_callback_success_slo', { outcome: 'below_threshold', thresholdPermille: 995 });
      }
      if (sessionCount >= 100) {
        const rank = Number((BigInt(sessionCount) * 95n + 99n) / 100n);
        let cumulative = 0;
        const bucket = sessionBuckets.findIndex((count) => (cumulative += count) >= rank);
        if (bucket >= AUTH_SESSION_HISTOGRAM_BOUNDS_SECONDS.findIndex((bound) => bound === 0.02) + 1) {
          alerts.emit('session_lookup_latency_slo', { outcome: 'above_threshold', thresholdMs: 20 });
        }
      }
      let criticalIncidentCount = 0;
      for (const [type, count] of alertCounts) {
        if (CRITICAL_ALERTS.has(type)) criticalIncidentCount = addBounded(criticalIncidentCount, count);
      }
      const snapshotGaps = [...gaps].map(([code, count]) => ({ code, count }));
      const snapshot: AuthRolloutSnapshot = {
        contract: AUTH_ROLLOUT_CONTRACT,
        interval: { start: new Date(intervalStart).toISOString(), end: new Date(end).toISOString() },
        instanceId,
        sequence: sequence += 1,
        counters: [...counters.values()],
        histograms: [...histograms.values()].map((histogram): AuthRolloutHistogram => ({
          metric: histogram.metric,
          dimensions: histogram.dimensions,
          unit: 'seconds',
          bounds: AUTH_SESSION_HISTOGRAM_BOUNDS_SECONDS,
          bucketCounts: histogram.bucketCounts,
          count: histogram.count
        })),
        alerts: Object.fromEntries(alertCounts),
        criticalIncidentCount,
        observability: { status: snapshotGaps.length === 0 ? 'healthy' : 'degraded', gaps: snapshotGaps }
      };
      intervalStart = end;
      callbackSuccess = 0;
      callbackFailure = 0;
      counters.clear();
      histograms.clear();
      alertCounts.clear();
      gaps.clear();
      if (inFlight) {
        for (const gap of snapshotGaps) gaps.set(gap.code, gap.count);
        markGap('sink_backpressure');
        return undefined;
      }
      try {
        const result = sink(snapshot);
        if (result && typeof result.then === 'function') {
          inFlight = true;
          let settled = false;
          const timer = setTimeout(() => {
            if (settled) return;
            settled = true;
            inFlight = false;
            markGap('sink_timeout');
          }, sinkTimeoutMs);
          timer.unref();
          void Promise.resolve(result).then(() => {
            if (settled) return;
            settled = true;
            inFlight = false;
            clearTimeout(timer);
          }, () => {
            if (settled) return;
            settled = true;
            inFlight = false;
            clearTimeout(timer);
            for (const gap of snapshotGaps) gaps.set(gap.code, (gaps.get(gap.code) ?? 0) + gap.count);
            markGap('sink_rejected');
          });
        }
      } catch {
        for (const gap of snapshotGaps) gaps.set(gap.code, gap.count);
        markGap('sink_throw');
        return undefined;
      }
      return snapshot;
    }
  };
}

export function registerAuthTelemetryLifecycle(
  app: FastifyInstance,
  telemetry: StructuredAuthTelemetry,
  intervalMs = 60_000
) {
  const timer = setInterval(() => telemetry.flush(), intervalMs);
  timer.unref();
  app.addHook('onClose', async () => {
    clearInterval(timer);
    telemetry.flush();
  });
  return timer;
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
