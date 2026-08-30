import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import { performance } from 'node:perf_hooks';
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
  | 'session_lookup_latency_slo'
  | 'cross_tenant_access_denied'
  | 'provider_configuration_drift'
  | 'session_revocation_slo'
  | 'unusual_session_creation'
  | 'recovery_revocation_slo_breach';

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

export type AuthAlertRoute = 'security' | 'identity' | 'abuse' | 'database';
export type AuthAlertRoutingConfig = Readonly<Record<AuthAlertType, readonly AuthAlertRoute[]>>;
export type AuthAlertDelivery = {
  contract: 'egogero.auth-alert-delivery/v1';
  type: AuthAlertType;
  routes: readonly AuthAlertRoute[];
};
export type AuthAlertDeliveryResult = { acknowledged: boolean };
export type AuthAlertDeliveryOperation = Promise<AuthAlertDeliveryResult>
  | { promise: Promise<AuthAlertDeliveryResult>; cancel?: () => void };
export type AuthAlertDeliveryAdapter = (delivery: AuthAlertDelivery, signal: AbortSignal) => AuthAlertDeliveryOperation;

export const DEFAULT_AUTH_ALERT_ROUTES: AuthAlertRoutingConfig = {
  rate_limit_repeated_excess: ['abuse'],
  crypto_integrity_failure: ['security'],
  crypto_key_failure: ['security'],
  oidc_replay_or_state_miss: ['security', 'identity'],
  oidc_issuer_mixup: ['security', 'identity'],
  oidc_callback_success_slo: ['identity'],
  session_lookup_latency_slo: ['database', 'identity'],
  cross_tenant_access_denied: ['security'],
  provider_configuration_drift: ['security', 'identity'],
  session_revocation_slo: ['security', 'identity'],
  unusual_session_creation: ['security', 'abuse'],
  recovery_revocation_slo_breach: ['security', 'identity']
};

const AUTH_ALERT_TYPES: readonly AuthAlertType[] = [
  'rate_limit_repeated_excess', 'crypto_integrity_failure', 'crypto_key_failure',
  'oidc_replay_or_state_miss', 'oidc_issuer_mixup', 'oidc_callback_success_slo',
  'session_lookup_latency_slo', 'cross_tenant_access_denied', 'provider_configuration_drift',
  'session_revocation_slo', 'unusual_session_creation', 'recovery_revocation_slo_breach'
];
const AUTH_ALERT_ROUTES = new Set<AuthAlertRoute>(['security', 'identity', 'abuse', 'database']);

export function createRoutedAuthAlertSink(
  config: AuthAlertRoutingConfig,
  adapter: AuthAlertDeliveryAdapter,
  options: {
    timeoutMs?: number;
    onGap?: (code: Extract<AuthRolloutSnapshot['observability']['gaps'][number]['code'], `alert_route_${string}`>) => void;
  } = {}
) {
  const timeoutMs = options.timeoutMs ?? 5_000;
  if (!Number.isFinite(timeoutMs) || timeoutMs < 1
    || Object.keys(config).length !== AUTH_ALERT_TYPES.length
    || !AUTH_ALERT_TYPES.every((type) => Array.isArray(config[type])
      && config[type].length > 0
      && config[type].length <= AUTH_ALERT_ROUTES.size
      && new Set(config[type]).size === config[type].length
      && config[type].every((route) => AUTH_ALERT_ROUTES.has(route)))) {
    throw new Error('Invalid bounded auth alert routing configuration');
  }
  const routes = AUTH_ALERT_TYPES.reduce((bounded, type) => {
    bounded[type] = [...config[type]];
    return bounded;
  }, {} as Record<AuthAlertType, readonly AuthAlertRoute[]>);
  let active: { controller: AbortController; timedOut: boolean; cancel?: () => void } | null = null;
  let pending: AuthAlertDelivery | null = null;
  function gap(code: Parameters<NonNullable<typeof options.onGap>>[0]) {
    try { options.onGap?.(code); } catch { /* observability cannot affect auth */ }
  }
  function dispatch(delivery: AuthAlertDelivery) {
    const controller = new AbortController();
    try {
      const result = adapter(delivery, controller.signal);
      const operation = result instanceof Promise ? { promise: result } : result;
      if (!operation?.promise || typeof operation.promise.then !== 'function') {
        throw new Error('Invalid auth alert adapter operation');
      }
      const state = { controller, timedOut: false, cancel: operation.cancel };
      active = state;
      const timer = setTimeout(() => {
        if (active !== state || state.timedOut) return;
        state.timedOut = true;
        gap('alert_route_timeout');
        controller.abort();
        try { state.cancel?.(); } catch { /* cancellation is best effort */ }
      }, timeoutMs);
      timer.unref();
      void operation.promise.then((ack) => {
        if (ack?.acknowledged !== true) gap('alert_route_unacknowledged');
        settle(state);
      }, () => {
        gap('alert_route_rejected');
        settle(state);
      });
      function settle(expected: typeof state) {
        if (active !== expected) return;
        clearTimeout(timer);
        active = null;
        if (pending) {
          const next = pending;
          pending = null;
          dispatch(next);
        }
      }
    } catch {
      gap('alert_route_throw');
    }
  }
  const sink: AuthAlertSink = {
    emit(type) {
      const delivery: AuthAlertDelivery = {
        contract: 'egogero.auth-alert-delivery/v1', type, routes: [...routes[type]]
      };
      if (!active) dispatch(delivery);
      else if (!pending) pending = delivery;
      else gap('alert_route_backpressure');
    }
  };
  return { sink, state: () => ({ inFlight: active !== null, pending: pending ? 1 : 0 }) };
}

export function combineAuthAlertSinks(...sinks: readonly AuthAlertSink[]): AuthAlertSink {
  return {
    emit(type, details) {
      for (const sink of sinks) {
        try { void Promise.resolve(sink.emit(type, details)).catch(() => {}); } catch { /* non-authoritative */ }
      }
    }
  };
}

export function createAuthAlertStdoutAdapter(stream: NodeJS.WriteStream = process.stdout): AuthAlertDeliveryAdapter {
  return async (delivery, signal) => {
    if (!stream.write(`${JSON.stringify(delivery)}\n`)) {
      await new Promise<void>((resolve, reject) => {
        function cleanup() {
          stream.off('drain', drained);
          stream.off('error', failed);
          signal.removeEventListener('abort', aborted);
        }
        function drained() { cleanup(); resolve(); }
        function failed(error: Error) { cleanup(); reject(error); }
        function aborted() { cleanup(); reject(new Error('Auth alert stdout delivery aborted')); }
        stream.once('drain', drained);
        stream.once('error', failed);
        signal.addEventListener('abort', aborted, { once: true });
      });
    }
    return { acknowledged: true };
  };
}

export function createAuthAlertWebhookAdapter(
  url: string,
  request: typeof fetch = fetch
): AuthAlertDeliveryAdapter {
  const endpoint = new URL(url);
  if (endpoint.protocol !== 'https:' || endpoint.username || endpoint.password || endpoint.search || endpoint.hash) {
    throw new Error('Auth alert webhook must be an HTTPS URL without credentials, query, or fragment');
  }
  return async (delivery, signal) => {
    const response = await request(endpoint, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(delivery), signal
    });
    return { acknowledged: response.ok };
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

export type AuthSinkOperation = Promise<void> | { promise: Promise<void>; cancel?: () => void };
export type AuthSnapshotSink = (snapshot: AuthRolloutSnapshot) => void | AuthSinkOperation;

export type StructuredAuthTelemetry = {
  metrics: AuthMetrics;
  alerts: AuthAlertSink;
  flush(): AuthRolloutSnapshot | undefined;
  recordObservabilityGap(code: AuthRolloutSnapshot['observability']['gaps'][number]['code']): void;
  sinkState(): { inFlight: boolean; pending: number };
};

const CRITICAL_ALERTS = new Set<AuthAlertType>([
  'crypto_integrity_failure', 'crypto_key_failure', 'oidc_replay_or_state_miss', 'oidc_issuer_mixup',
  'cross_tenant_access_denied', 'provider_configuration_drift', 'session_revocation_slo',
  'unusual_session_creation', 'recovery_revocation_slo_breach'
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
  let waitingDrain: Promise<void> | null = null;
  return (snapshot) => {
    if (stream.write(`${JSON.stringify(snapshot)}\n`)) return;
    waitingDrain ??= new Promise<void>((resolve, reject) => {
      function cleanup() {
        stream.off('drain', drained);
        stream.off('error', failed);
        waitingDrain = null;
      }
      function drained() { cleanup(); resolve(); }
      function failed(error: Error) { cleanup(); reject(error); }
      stream.once('drain', drained);
      stream.once('error', failed);
    });
    return waitingDrain;
  };
}

export function createAuthSnapshotFileSink(path: string, options: { maxBytes?: number } = {}): AuthSnapshotSink {
  const maxBytes = options.maxBytes ?? 32 * 1_024 * 1_024;
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) throw new Error('Invalid auth snapshot sink limit');
  let writes = Promise.resolve();
  return (snapshot) => {
    writes = writes.catch(() => {}).then(async () => {
      const encoded = Buffer.from(`${JSON.stringify(snapshot)}\n`, 'utf8');
      const handle = await open(path, constants.O_APPEND | constants.O_CREAT | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
      try {
        const metadata = await handle.stat();
        if (!metadata.isFile()) throw new Error('Auth snapshot sink must be a regular file');
        if ((metadata.mode & 0o777) !== 0o600) await handle.chmod(0o600);
        if (metadata.size > maxBytes - encoded.length) throw new Error('Auth snapshot sink limit exceeded');
        await handle.write(encoded);
        await handle.sync();
      } finally {
        await handle.close();
      }
    });
    return writes;
  };
}

export async function prepareAuthSnapshotFile(path: string, maxBytes = 32 * 1_024 * 1_024) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) throw new Error('Invalid auth snapshot sink limit');
  const handle = await open(path, constants.O_APPEND | constants.O_CREAT | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
  try {
    const metadata = await handle.stat();
    if (!metadata.isFile()) throw new Error('Auth snapshot sink must be a regular file');
    if (metadata.size > maxBytes) throw new Error('Auth snapshot sink limit exceeded');
    if ((metadata.mode & 0o777) !== 0o600) await handle.chmod(0o600);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

export function createStructuredAuthTelemetry(
  sink: AuthSnapshotSink = createAuthSnapshotStdoutSink(),
  options: {
    instanceId: string;
    stageId: string;
    now?: () => number;
    monotonicNow?: () => number;
    maxClockDriftMs?: number;
    sinkTimeoutMs?: number;
  }
): StructuredAuthTelemetry {
  const { instanceId, stageId } = options;
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(instanceId)) {
    throw new Error('Auth telemetry instanceId must be an injected non-sensitive UUID v4');
  }
  if (!/^(?:staging|production):[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/.test(stageId)) {
    throw new Error('Auth telemetry stageId must be an injected bounded deployment stage');
  }
  const now = options.now ?? Date.now;
  const monotonicNow = options.monotonicNow ?? (options.now ? now : performance.now.bind(performance));
  const maxClockDriftMs = options.maxClockDriftMs ?? 5_000;
  const sinkTimeoutMs = options.sinkTimeoutMs ?? 5_000;
  if (!Number.isFinite(maxClockDriftMs) || maxClockDriftMs < 0
    || !Number.isFinite(sinkTimeoutMs) || sinkTimeoutMs < 1) throw new Error('Invalid auth telemetry timing configuration');
  const counters = new Map<string, AuthRolloutCounter>();
  const histograms = new Map<string, { metric: AuthMetricName; dimensions: Record<string, string>; bucketCounts: number[]; count: number }>();
  const alertCounts = new Map<AuthAlertType, number>();
  const gaps = new Map<AuthRolloutSnapshot['observability']['gaps'][number]['code'], number>();
  let callbackSuccess = 0;
  let callbackFailure = 0;
  let intervalStart = now();
  let monotonicStart = monotonicNow();
  let sequence = 0;
  let active: { timedOut: boolean; cancel?: () => void } | null = null;
  let pending: AuthRolloutSnapshot | null = null;
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
  function restoreSnapshotGaps(snapshot: AuthRolloutSnapshot) {
    for (const gap of snapshot.observability.gaps) {
      gaps.set(gap.code, addBounded(gaps.get(gap.code) ?? 0, gap.count));
    }
  }
  function attachCurrentGaps(snapshot: AuthRolloutSnapshot) {
    if (gaps.size === 0) return snapshot;
    const merged = new Map(snapshot.observability.gaps.map((gap) => [gap.code, gap.count]));
    for (const [code, count] of gaps) merged.set(code, addBounded(merged.get(code) ?? 0, count));
    gaps.clear();
    return {
      ...snapshot,
      observability: { status: 'degraded' as const, gaps: [...merged].map(([code, count]) => ({ code, count })) }
    };
  }
  function dispatch(snapshot: AuthRolloutSnapshot) {
    try {
      const result = sink(snapshot);
      if (!result) return;
      const operation = result instanceof Promise ? { promise: result } : result;
      if (!operation?.promise || typeof operation.promise.then !== 'function') {
        throw new Error('Invalid auth snapshot sink operation');
      }
      const state = { timedOut: false, cancel: operation.cancel };
      active = state;
      const timer = setTimeout(() => {
        if (active !== state || state.timedOut) return;
        state.timedOut = true;
        markGap('sink_timeout');
        try { state.cancel?.(); } catch { /* cancellation is best effort */ }
      }, sinkTimeoutMs);
      timer.unref();
      void operation.promise.then(() => settle(state), () => {
        restoreSnapshotGaps(snapshot);
        markGap('sink_rejected');
        settle(state);
      });
      function settle(expected: typeof state) {
        if (active !== expected) return;
        clearTimeout(timer);
        active = null;
        if (pending) {
          const next = attachCurrentGaps(pending);
          pending = null;
          dispatch(next);
        }
      }
    } catch {
      restoreSnapshotGaps(snapshot);
      markGap('sink_throw');
    }
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
    recordObservabilityGap: markGap,
    sinkState() { return { inFlight: active !== null, pending: pending ? 1 : 0 }; },
    flush() {
      const observedEnd = now();
      const observedMonotonicEnd = monotonicNow();
      const monotonicElapsed = observedMonotonicEnd - monotonicStart;
      if (!Number.isFinite(observedEnd) || !Number.isFinite(monotonicElapsed) || monotonicElapsed <= 0) markGap('clock_anomaly');
      const safeMonotonicElapsed = Number.isFinite(monotonicElapsed) && monotonicElapsed > 0 ? monotonicElapsed : 1;
      const wallElapsed = observedEnd - intervalStart;
      const drifted = Number.isFinite(wallElapsed) && Math.abs(wallElapsed - safeMonotonicElapsed) > maxClockDriftMs;
      if (drifted) markGap('clock_drift');
      const end = Number.isFinite(observedEnd) && wallElapsed > 0 && !drifted
        ? observedEnd
        : intervalStart + safeMonotonicElapsed;
      monotonicStart = Number.isFinite(observedMonotonicEnd) ? observedMonotonicEnd : monotonicStart + safeMonotonicElapsed;
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
        stageId,
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
      if (active) {
        if (!pending) pending = snapshot;
        else {
          restoreSnapshotGaps(snapshot);
          markGap('sink_backpressure');
        }
        return snapshot;
      }
      dispatch(snapshot);
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
