import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

export const AUTH_ROLLOUT_CONTRACT = 'egogero.auth-rollout/v1' as const;
export const AUTH_ROLLOUT_MINIMUM_WINDOW_MS = 24 * 60 * 60 * 1_000;
export const AUTH_ROLLOUT_MINIMUM_CALLBACKS = 100;
export const AUTH_ROLLOUT_MINIMUM_SESSION_SAMPLES = 100;
export const AUTH_SESSION_HISTOGRAM_BOUNDS_SECONDS = [
  0.001, 0.0025, 0.005, 0.01, 0.02, 0.05, 0.1, 0.25, 0.5, 1
] as const;
const COUNTER_DIMENSIONS: Readonly<Record<string, Readonly<Record<string, readonly string[]>>>> = {
  auth_oidc_callback_total: { outcome: ['success', 'failure', 'other'], reason: ['none', 'state', 'issuer', 'crypto', 'account', 'validation', 'other'] },
  auth_session_lookup_total: { operation: ['authenticate', 'inspect', 'other'], outcome: ['hit', 'miss', 'failure', 'other'] },
  auth_database_writes_total: { operation: ['recovery', 'session_issue', 'session_rotate', 'session_revoke', 'other'], outcome: ['success', 'failure', 'other'] },
  auth_rate_limit_decisions_total: {
    operation: ['login_ip', 'callback_failure_ip', 'session_issue_account', 'recovery_ip', 'reauthentication_account', 'authentication_failure_ip', 'other'],
    outcome: ['allowed', 'denied', 'other']
  }
};
const HISTOGRAM_DIMENSIONS: Readonly<Record<string, Readonly<Record<string, readonly string[]>>>> = {
  auth_session_lookup_seconds: { operation: ['authenticate', 'inspect', 'other'], outcome: ['hit', 'miss', 'failure', 'other'] },
  auth_session_database_seconds: { operation: ['authenticate', 'inspect', 'other'], outcome: ['hit', 'miss', 'failure', 'other'] },
  auth_session_revocation_seconds: { operation: ['current', 'other'], outcome: ['revoked', 'already-revoked', 'unavailable', 'other'] }
};
const ALERT_TYPES = new Set([
  'rate_limit_repeated_excess', 'crypto_integrity_failure', 'crypto_key_failure', 'oidc_replay_or_state_miss',
  'oidc_issuer_mixup', 'oidc_callback_success_slo', 'session_lookup_latency_slo'
]);
const CRITICAL_ALERT_TYPES = new Set([
  'crypto_integrity_failure', 'crypto_key_failure', 'oidc_replay_or_state_miss', 'oidc_issuer_mixup'
]);
const INSTANCE_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export type AuthRolloutCounter = {
  metric: string;
  dimensions: Readonly<Record<string, string>>;
  value: number;
};

export type AuthRolloutHistogram = {
  metric: string;
  dimensions: Readonly<Record<string, string>>;
  unit: 'seconds';
  bounds: readonly number[];
  bucketCounts: readonly number[];
  count: number;
};

export type AuthRolloutSnapshot = {
  contract: typeof AUTH_ROLLOUT_CONTRACT;
  interval: { start: string; end: string };
  instanceId: string;
  sequence: number;
  counters: readonly AuthRolloutCounter[];
  histograms: readonly AuthRolloutHistogram[];
  alerts: Readonly<Record<string, number>>;
  criticalIncidentCount: number;
  observability: {
    status: 'healthy' | 'degraded';
    gaps: readonly { code: 'sink_throw' | 'sink_rejected' | 'sink_timeout' | 'sink_backpressure' | 'numeric_saturation' | 'clock_anomaly'; count: number }[];
  };
};

export type AuthRolloutEvaluation = {
  contract: 'egogero.auth-rollout-evaluation/v1';
  result: 'pass' | 'fail' | 'inconclusive';
  window: { start: string | null; end: string | null; durationMs: number };
  totals: {
    callbacks: number;
    callbackSuccess: number;
    callbackSuccessPermille: number | null;
    sessionSamples: number;
    sessionP95Ms: number | 'over_1000' | null;
    criticalIncidents: number;
  };
  reasons: readonly string[];
};

function safeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function canonicalInstant(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) && new Date(timestamp).toISOString() === value;
}

function validDimensions(value: unknown, policy: Readonly<Record<string, readonly string[]>> | undefined) {
  if (!policy || !value || typeof value !== 'object' || Array.isArray(value)) return false;
  const entries = Object.entries(value);
  return entries.length === Object.keys(policy).length
    && entries.every(([key, dimension]) => typeof dimension === 'string' && policy[key]?.includes(dimension));
}

function validSnapshot(value: unknown): value is AuthRolloutSnapshot {
  if (!value || typeof value !== 'object') return false;
  const snapshot = value as Partial<AuthRolloutSnapshot>;
  if (snapshot.contract !== AUTH_ROLLOUT_CONTRACT
    || typeof snapshot.instanceId !== 'string'
    || !INSTANCE_ID.test(snapshot.instanceId)
    || !safeInteger(snapshot.sequence)
    || snapshot.sequence < 1
    || !snapshot.interval
    || !canonicalInstant(snapshot.interval.start)
    || !canonicalInstant(snapshot.interval.end)
    || Date.parse(snapshot.interval.end) <= Date.parse(snapshot.interval.start)
    || !Array.isArray(snapshot.counters)
    || !Array.isArray(snapshot.histograms)
    || !snapshot.alerts
    || !safeInteger(snapshot.criticalIncidentCount)
    || !snapshot.observability
    || !Array.isArray(snapshot.observability.gaps)) return false;
  const counters = snapshot.counters as AuthRolloutCounter[];
  const histograms = snapshot.histograms as AuthRolloutHistogram[];
  const alerts = snapshot.alerts as Record<string, number>;
  const gaps = snapshot.observability.gaps as AuthRolloutSnapshot['observability']['gaps'];
  const criticalCount = Object.entries(alerts).reduce((total, [type, count]) =>
    total + (CRITICAL_ALERT_TYPES.has(type) && safeInteger(count) ? BigInt(count) : 0n), 0n);
  return counters.every((counter) => safeInteger(counter.value)
      && validDimensions(counter.dimensions, COUNTER_DIMENSIONS[counter.metric]))
    && histograms.every((histogram) => histogram.unit === 'seconds'
      && validDimensions(histogram.dimensions, HISTOGRAM_DIMENSIONS[histogram.metric])
      && safeInteger(histogram.count)
      && Array.isArray(histogram.bounds)
      && histogram.bounds.length === AUTH_SESSION_HISTOGRAM_BOUNDS_SECONDS.length
      && histogram.bounds.every((bound: number, index: number) => bound === AUTH_SESSION_HISTOGRAM_BOUNDS_SECONDS[index])
      && Array.isArray(histogram.bucketCounts)
      && histogram.bucketCounts.length === histogram.bounds.length + 1
      && histogram.bucketCounts.every(safeInteger)
      && histogram.bucketCounts.reduce((sum: bigint, count: number) => sum + BigInt(count), 0n) === BigInt(histogram.count))
    && Object.entries(alerts).every(([type, count]) => ALERT_TYPES.has(type) && safeInteger(count))
    && criticalCount === BigInt(snapshot.criticalIncidentCount)
    && ['healthy', 'degraded'].includes(snapshot.observability.status)
    && gaps.every((gap) => ['sink_throw', 'sink_rejected', 'sink_timeout', 'sink_backpressure', 'numeric_saturation', 'clock_anomaly'].includes(gap.code)
      && safeInteger(gap.count) && gap.count > 0)
    && (snapshot.observability.status === 'degraded') === (gaps.length > 0);
}

function addSafe(left: number, right: number): number | null {
  const sum = left + right;
  return Number.isSafeInteger(sum) ? sum : null;
}

export function evaluateAuthRolloutSnapshots(input: readonly unknown[]): AuthRolloutEvaluation {
  const reasons = new Set<string>();
  const snapshots: AuthRolloutSnapshot[] = [];
  for (const value of input) {
    if (validSnapshot(value)) snapshots.push(value);
    else reasons.add('invalid_snapshot');
  }

  const intervals = snapshots.map((snapshot) => ({
    start: Date.parse(snapshot.interval.start), end: Date.parse(snapshot.interval.end), snapshot
  })).sort((left, right) => left.start - right.start || left.end - right.end);
  const byInstance = new Map<string, typeof intervals>();
  for (const interval of intervals) {
    const list = byInstance.get(interval.snapshot.instanceId) ?? [];
    list.push(interval);
    byInstance.set(interval.snapshot.instanceId, list);
  }
  for (const list of byInstance.values()) {
    list.sort((left, right) => left.start - right.start || left.snapshot.sequence - right.snapshot.sequence);
    for (let index = 1; index < list.length; index += 1) {
      if (list[index].snapshot.sequence !== list[index - 1].snapshot.sequence + 1) reasons.add('instance_sequence_invalid');
      if (list[index].start < list[index - 1].end) reasons.add('instance_interval_overlap');
      if (list[index].start > list[index - 1].end) reasons.add('instance_interval_gap');
    }
  }

  let coverageStart: number | null = null;
  let coverageEnd: number | null = null;
  for (const interval of intervals) {
    if (coverageStart === null) {
      coverageStart = interval.start;
      coverageEnd = interval.end;
    } else if (interval.start > coverageEnd!) {
      reasons.add('window_gap');
      coverageEnd = interval.end;
    } else {
      coverageEnd = Math.max(coverageEnd!, interval.end);
    }
  }
  const durationMs = coverageStart === null ? 0 : coverageEnd! - coverageStart;
  if (durationMs < AUTH_ROLLOUT_MINIMUM_WINDOW_MS) reasons.add('window_below_24h');

  let callbackSuccess = 0;
  let callbackFailure = 0;
  let criticalIncidents = 0;
  const sessionBuckets = Array(AUTH_SESSION_HISTOGRAM_BOUNDS_SECONDS.length + 1).fill(0) as number[];
  for (const snapshot of snapshots) {
    if (snapshot.observability.status !== 'healthy' || snapshot.observability.gaps.length > 0) reasons.add('observability_gap');
    if (snapshot.counters.some((counter) => Object.values(counter.dimensions).includes('other'))
      || snapshot.histograms.some((histogram) => Object.values(histogram.dimensions).includes('other'))) {
      reasons.add('unexpected_dimension');
    }
    const criticalTotal = addSafe(criticalIncidents, snapshot.criticalIncidentCount);
    if (criticalTotal === null) reasons.add('numeric_overflow');
    else criticalIncidents = criticalTotal;
    for (const counter of snapshot.counters) {
      if (counter.metric !== 'auth_oidc_callback_total') continue;
      if (counter.dimensions.outcome === 'success') {
        const total = addSafe(callbackSuccess, counter.value);
        if (total === null) reasons.add('numeric_overflow'); else callbackSuccess = total;
      } else if (counter.dimensions.outcome === 'failure') {
        const total = addSafe(callbackFailure, counter.value);
        if (total === null) reasons.add('numeric_overflow'); else callbackFailure = total;
      }
    }
    for (const histogram of snapshot.histograms) {
      if (histogram.metric !== 'auth_session_lookup_seconds') continue;
      for (let index = 0; index < sessionBuckets.length; index += 1) {
        const total = addSafe(sessionBuckets[index], histogram.bucketCounts[index]);
        if (total === null) reasons.add('numeric_overflow'); else sessionBuckets[index] = total;
      }
    }
  }
  const callbacks = callbackSuccess + callbackFailure;
  const sessionSamples = sessionBuckets.reduce((sum, count) => sum + count, 0);
  if (!Number.isSafeInteger(callbacks) || !Number.isSafeInteger(sessionSamples)) reasons.add('numeric_overflow');
  if (callbacks < AUTH_ROLLOUT_MINIMUM_CALLBACKS) reasons.add('callback_volume_insufficient');
  if (sessionSamples < AUTH_ROLLOUT_MINIMUM_SESSION_SAMPLES) reasons.add('session_volume_insufficient');

  let sessionP95Ms: number | 'over_1000' | null = null;
  if (sessionSamples > 0) {
    const rank = Number((BigInt(sessionSamples) * 95n + 99n) / 100n);
    let cumulative = 0;
    const bucketIndex = sessionBuckets.findIndex((count) => (cumulative += count) >= rank);
    sessionP95Ms = bucketIndex === AUTH_SESSION_HISTOGRAM_BOUNDS_SECONDS.length
      ? 'over_1000'
      : AUTH_SESSION_HISTOGRAM_BOUNDS_SECONDS[bucketIndex] * 1_000;
  }
  const callbackFails = callbacks >= AUTH_ROLLOUT_MINIMUM_CALLBACKS
    && BigInt(callbackSuccess) * 1_000n < BigInt(callbacks) * 995n;
  const latencyFails = sessionSamples >= AUTH_ROLLOUT_MINIMUM_SESSION_SAMPLES
    && sessionP95Ms !== null && (sessionP95Ms === 'over_1000' || sessionP95Ms > 20);
  if (criticalIncidents > 0) reasons.add('critical_auth_incident');
  if (callbackFails) reasons.add('callback_success_below_99_5_percent');
  if (latencyFails) reasons.add('session_p95_above_20ms');
  const failed = criticalIncidents > 0 || callbackFails || latencyFails;
  const inconclusiveReasons = [...reasons].filter((reason) => ![
    'critical_auth_incident', 'callback_success_below_99_5_percent', 'session_p95_above_20ms'
  ].includes(reason));

  return {
    contract: 'egogero.auth-rollout-evaluation/v1',
    result: failed ? 'fail' : inconclusiveReasons.length > 0 ? 'inconclusive' : 'pass',
    window: {
      start: coverageStart === null ? null : new Date(coverageStart).toISOString(),
      end: coverageEnd === null ? null : new Date(coverageEnd).toISOString(),
      durationMs
    },
    totals: {
      callbacks,
      callbackSuccess,
      callbackSuccessPermille: callbacks === 0 ? null
        : Number(BigInt(callbackSuccess) * 1_000_000n / BigInt(callbacks)) / 1_000,
      sessionSamples,
      sessionP95Ms,
      criticalIncidents
    },
    reasons: [...reasons].sort()
  };
}

export async function readAuthRolloutJsonl(paths: readonly string[]): Promise<unknown[]> {
  const sources = paths.length === 0 ? [await new Promise<string>((resolve, reject) => {
    let input = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk: string) => { input += chunk; });
    process.stdin.on('end', () => resolve(input));
    process.stdin.on('error', reject);
  })] : await Promise.all(paths.map((path) => readFile(path, 'utf8')));
  const values: unknown[] = [];
  for (const line of sources.flatMap((source) => source.split(/\r?\n/)).filter((line) => line.trim().length > 0)) {
    try { values.push(JSON.parse(line)); } catch { values.push(null); }
  }
  return values;
}

async function main() {
  const evaluation = evaluateAuthRolloutSnapshots(await readAuthRolloutJsonl(process.argv.slice(2)));
  process.stdout.write(`${JSON.stringify(evaluation)}\n`);
  process.exitCode = evaluation.result === 'pass' ? 0 : evaluation.result === 'fail' ? 1 : 2;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : 'evaluation failed'}\n`);
    process.exitCode = 2;
  });
}
