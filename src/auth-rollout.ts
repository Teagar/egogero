import { constants, createReadStream } from 'node:fs';
import { lstat, open } from 'node:fs/promises';
import { StringDecoder } from 'node:string_decoder';
import { pathToFileURL } from 'node:url';

export const AUTH_ROLLOUT_CONTRACT = 'egogero.auth-rollout/v1' as const;
export const AUTH_ROLLOUT_INVENTORY_CONTRACT = 'egogero.auth-rollout-inventory/v1' as const;
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
export type AuthRolloutInputLimits = {
  files: number;
  records: number;
  lineBytes: number;
  fileBytes: number;
  totalBytes: number;
  inventoryBytes: number;
};
export const AUTH_ROLLOUT_INPUT_LIMITS: AuthRolloutInputLimits = {
  files: 32,
  records: 100_000,
  lineBytes: 256 * 1_024,
  fileBytes: 32 * 1_024 * 1_024,
  totalBytes: 64 * 1_024 * 1_024,
  inventoryBytes: 256 * 1_024
} as const;

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
    gaps: readonly { code: 'sink_throw' | 'sink_rejected' | 'sink_timeout' | 'sink_backpressure' | 'numeric_saturation' | 'clock_anomaly' | 'clock_drift' | 'alert_route_throw' | 'alert_route_rejected' | 'alert_route_timeout' | 'alert_route_backpressure' | 'alert_route_unacknowledged'; count: number }[];
  };
};

export type AuthRolloutInventory = {
  contract: typeof AUTH_ROLLOUT_INVENTORY_CONTRACT;
  servingInstances: readonly {
    instanceId: string;
    expectedStart: string;
    expectedEnd: string;
    cadenceMs: number;
  }[];
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

function validInventory(value: unknown): value is AuthRolloutInventory {
  if (!value || typeof value !== 'object') return false;
  const inventory = value as Partial<AuthRolloutInventory>;
  if (inventory.contract !== AUTH_ROLLOUT_INVENTORY_CONTRACT
    || !Array.isArray(inventory.servingInstances)
    || inventory.servingInstances.length === 0
    || inventory.servingInstances.length > 1_000) return false;
  const identifiers = new Set<string>();
  return inventory.servingInstances.every((instance) => {
    if (!instance || typeof instance !== 'object'
      || !INSTANCE_ID.test(instance.instanceId)
      || identifiers.has(instance.instanceId)
      || !canonicalInstant(instance.expectedStart)
      || !canonicalInstant(instance.expectedEnd)
      || Date.parse(instance.expectedEnd) <= Date.parse(instance.expectedStart)
      || !safeInteger(instance.cadenceMs)
      || instance.cadenceMs < 1_000
      || instance.cadenceMs > 24 * 60 * 60_000) return false;
    identifiers.add(instance.instanceId);
    return true;
  });
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
    && gaps.every((gap) => ['sink_throw', 'sink_rejected', 'sink_timeout', 'sink_backpressure', 'numeric_saturation',
      'clock_anomaly', 'clock_drift', 'alert_route_throw', 'alert_route_rejected', 'alert_route_timeout',
      'alert_route_backpressure', 'alert_route_unacknowledged'].includes(gap.code)
      && safeInteger(gap.count) && gap.count > 0)
    && (snapshot.observability.status === 'degraded') === (gaps.length > 0);
}

function addSafe(left: number, right: number): number | null {
  const sum = left + right;
  return Number.isSafeInteger(sum) ? sum : null;
}

export function evaluateAuthRolloutSnapshots(
  input: readonly unknown[],
  inventoryInput?: unknown,
  inputReasons: readonly string[] = []
): AuthRolloutEvaluation {
  const reasons = new Set<string>(inputReasons);
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

  const inventory = validInventory(inventoryInput) ? inventoryInput : null;
  if (!inventoryInput) reasons.add('expected_inventory_missing');
  else if (!inventory) reasons.add('expected_inventory_invalid');
  if (inventory) {
    const expectedIds = new Set(inventory.servingInstances.map((instance) => instance.instanceId));
    if (intervals.some((interval) => !expectedIds.has(interval.snapshot.instanceId))) {
      reasons.add('snapshot_instance_unexpected');
    }
    for (const expected of inventory.servingInstances) {
      const expectedStart = Date.parse(expected.expectedStart);
      const expectedEnd = Date.parse(expected.expectedEnd);
      const list = byInstance.get(expected.instanceId) ?? [];
      let cursor = expectedStart;
      for (const interval of list) {
        if (interval.start < expectedStart || interval.end > expectedEnd) {
          reasons.add('snapshot_outside_expected_lifecycle');
          continue;
        }
        if (interval.end - interval.start > expected.cadenceMs) reasons.add('instance_cadence_exceeded');
        if (interval.start > cursor) reasons.add('expected_instance_interval_missing');
        cursor = Math.max(cursor, interval.end);
      }
      if (cursor < expectedEnd) reasons.add('expected_instance_interval_missing');
    }
  }

  let coverageStart: number | null = null;
  let coverageEnd: number | null = null;
  const servingIntervals = inventory
    ? inventory.servingInstances.map((instance) => ({
        start: Date.parse(instance.expectedStart), end: Date.parse(instance.expectedEnd)
      })).sort((left, right) => left.start - right.start || left.end - right.end)
    : intervals;
  for (const interval of servingIntervals) {
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

export class AuthRolloutInputLimitError extends Error {}

export async function readAuthRolloutJsonl(
  paths: readonly string[],
  limits: AuthRolloutInputLimits = AUTH_ROLLOUT_INPUT_LIMITS
): Promise<unknown[]> {
  if (paths.length > limits.files) throw new AuthRolloutInputLimitError('too many snapshot files');
  const values: unknown[] = [];
  let totalBytes = 0;
  const sourceNames: Array<string | null> = paths.length === 0 ? [null] : [...paths];
  for (const name of sourceNames) {
    const source = { name: name ?? 'stdin', stream: name
      ? createReadStream(name) as NodeJS.ReadableStream
      : process.stdin };
    let fileBytes = 0;
    let partial = '';
    const decoder = new StringDecoder('utf8');
    function consume(line: string) {
      if (Buffer.byteLength(line, 'utf8') > limits.lineBytes) {
        throw new AuthRolloutInputLimitError(`snapshot line limit exceeded at ${source.name}`);
      }
      if (line.trim().length === 0) return;
      if (values.length >= limits.records) throw new AuthRolloutInputLimitError('too many snapshot records');
      try { values.push(JSON.parse(line)); } catch { values.push(null); }
    }
    try {
      for await (const chunk of source.stream) {
        const bytes = typeof chunk === 'string' ? Buffer.byteLength(chunk, 'utf8') : chunk.length;
        fileBytes += bytes;
        totalBytes += bytes;
        if (fileBytes > limits.fileBytes || totalBytes > limits.totalBytes) {
          throw new AuthRolloutInputLimitError(`snapshot input limit exceeded at ${source.name}`);
        }
        partial += typeof chunk === 'string' ? chunk : decoder.write(chunk);
        let newline = partial.indexOf('\n');
        while (newline >= 0) {
          const line = partial.slice(0, newline).replace(/\r$/, '');
          partial = partial.slice(newline + 1);
          consume(line);
          newline = partial.indexOf('\n');
        }
        if (Buffer.byteLength(partial, 'utf8') > limits.lineBytes) {
          throw new AuthRolloutInputLimitError(`snapshot line limit exceeded at ${source.name}`);
        }
      }
      partial += decoder.end();
      if (partial.length > 0) consume(partial.replace(/\r$/, ''));
    } catch (error) {
      if ('destroy' in source.stream && typeof source.stream.destroy === 'function') source.stream.destroy();
      throw error;
    }
  }
  return values;
}

export async function readAuthRolloutInventory(
  path: string,
  options: { chunkBytes?: number; afterOpen?: () => void | Promise<void> } = {}
): Promise<unknown> {
  const chunkBytes = options.chunkBytes ?? 64 * 1_024;
  if (!Number.isSafeInteger(chunkBytes) || chunkBytes < 1 || chunkBytes > 64 * 1_024) {
    throw new AuthRolloutInputLimitError('invalid inventory read chunk size');
  }
  const pathBeforeOpen = await lstat(path);
  if (!pathBeforeOpen.isFile()) throw new AuthRolloutInputLimitError('inventory must be a regular file');
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const initial = await handle.stat();
    if (!initial.isFile() || initial.dev !== pathBeforeOpen.dev || initial.ino !== pathBeforeOpen.ino) {
      throw new AuthRolloutInputLimitError('inventory changed before it was opened');
    }
    if (initial.size > AUTH_ROLLOUT_INPUT_LIMITS.inventoryBytes) {
      throw new AuthRolloutInputLimitError('inventory input limit exceeded');
    }
    await options.afterOpen?.();
    const decoder = new StringDecoder('utf8');
    const buffer = Buffer.allocUnsafe(chunkBytes);
    let partial = '';
    let bytes = 0;
    let records = 0;
    let inventory: unknown;
    function consume(line: string) {
      if (Buffer.byteLength(line, 'utf8') > AUTH_ROLLOUT_INPUT_LIMITS.inventoryBytes) {
        throw new AuthRolloutInputLimitError('inventory line limit exceeded');
      }
      if (line.trim().length === 0) return;
      records += 1;
      if (records > 1) throw new AuthRolloutInputLimitError('inventory must contain exactly one JSON record');
      inventory = JSON.parse(line) as unknown;
    }
    while (true) {
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      bytes += bytesRead;
      if (bytes > AUTH_ROLLOUT_INPUT_LIMITS.inventoryBytes) {
        throw new AuthRolloutInputLimitError('inventory input limit exceeded');
      }
      partial += decoder.write(buffer.subarray(0, bytesRead));
      let newline = partial.indexOf('\n');
      while (newline >= 0) {
        consume(partial.slice(0, newline).replace(/\r$/, ''));
        partial = partial.slice(newline + 1);
        newline = partial.indexOf('\n');
      }
      if (Buffer.byteLength(partial, 'utf8') > AUTH_ROLLOUT_INPUT_LIMITS.inventoryBytes) {
        throw new AuthRolloutInputLimitError('inventory line limit exceeded');
      }
    }
    partial += decoder.end();
    if (partial.length > 0) consume(partial.replace(/\r$/, ''));
    if (records !== 1) throw new AuthRolloutInputLimitError('inventory must contain exactly one JSON record');
    const finalHandle = await handle.stat();
    const finalPath = await lstat(path);
    if (finalHandle.size !== initial.size || finalPath.dev !== initial.dev || finalPath.ino !== initial.ino
      || !finalPath.isFile()) throw new AuthRolloutInputLimitError('inventory changed while being read');
    return inventory;
  } finally {
    await handle.close();
  }
}

async function main() {
  const args = process.argv.slice(2);
  const manifestIndex = args.indexOf('--inventory');
  const inventoryPath = manifestIndex >= 0 ? args[manifestIndex + 1] : undefined;
  const paths = manifestIndex < 0
    ? args
    : args.filter((_, index) => index !== manifestIndex && index !== manifestIndex + 1);
  let snapshots: unknown[] = [];
  let inventory: unknown;
  const inputReasons: string[] = [];
  if (manifestIndex >= 0 && !inventoryPath) inputReasons.push('input_read_error');
  try {
    snapshots = await readAuthRolloutJsonl(paths);
    if (inventoryPath) inventory = await readAuthRolloutInventory(inventoryPath);
  } catch (error) {
    inputReasons.push(error instanceof AuthRolloutInputLimitError ? 'input_limit_exceeded' : 'input_read_error');
  }
  const evaluation = evaluateAuthRolloutSnapshots(snapshots, inventory, inputReasons);
  process.stdout.write(`${JSON.stringify(evaluation)}\n`);
  process.exitCode = evaluation.result === 'pass' ? 0 : evaluation.result === 'fail' ? 1 : 2;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : 'evaluation failed'}\n`);
    process.exitCode = 2;
  });
}
