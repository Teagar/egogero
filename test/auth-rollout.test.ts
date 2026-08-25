import assert from 'node:assert/strict';
import test from 'node:test';

import {
  AUTH_ROLLOUT_CONTRACT,
  AUTH_SESSION_HISTOGRAM_BOUNDS_SECONDS,
  evaluateAuthRolloutSnapshots,
  type AuthRolloutSnapshot
} from '../src/auth-rollout.js';
import { createStructuredAuthTelemetry, type AuthSnapshotSink } from '../src/auth-observability.js';

const start = Date.parse('2026-08-01T00:00:00.000Z');

function snapshot(overrides: Partial<AuthRolloutSnapshot> = {}): AuthRolloutSnapshot {
  const buckets = [0, 0, 0, 0, 95, 5, 0, 0, 0, 0, 0];
  return {
    contract: AUTH_ROLLOUT_CONTRACT,
    interval: { start: new Date(start).toISOString(), end: new Date(start + 24 * 60 * 60_000).toISOString() },
    instanceId: '00000000-0000-4000-8000-000000000001',
    sequence: 1,
    counters: [
      { metric: 'auth_oidc_callback_total', dimensions: { outcome: 'success', reason: 'none' }, value: 199 },
      { metric: 'auth_oidc_callback_total', dimensions: { outcome: 'failure', reason: 'validation' }, value: 1 }
    ],
    histograms: [{
      metric: 'auth_session_lookup_seconds', dimensions: { operation: 'authenticate', outcome: 'hit' },
      unit: 'seconds', bounds: AUTH_SESSION_HISTOGRAM_BOUNDS_SECONDS, bucketCounts: buckets, count: 100
    }],
    alerts: {},
    criticalIncidentCount: 0,
    observability: { status: 'healthy', gaps: [] },
    ...overrides
  };
}

test('rollout evaluator passes exact callback, latency, and 24 hour boundaries', () => {
  const result = evaluateAuthRolloutSnapshots([snapshot()]);
  assert.equal(result.result, 'pass');
  assert.equal(result.totals.callbackSuccessPermille, 995);
  assert.equal(result.totals.sessionP95Ms, 20);
  assert.equal(result.window.durationMs, 24 * 60 * 60_000);
});

test('rollout evaluator aggregates concurrent instances without averaging percentiles', () => {
  const slow = snapshot({
    instanceId: '00000000-0000-4000-8000-000000000002',
    counters: [{ metric: 'auth_oidc_callback_total', dimensions: { outcome: 'success', reason: 'none' }, value: 200 }],
    histograms: [{
      metric: 'auth_session_lookup_seconds', dimensions: { operation: 'inspect', outcome: 'hit' }, unit: 'seconds',
      bounds: AUTH_SESSION_HISTOGRAM_BOUNDS_SECONDS, bucketCounts: [0, 0, 0, 0, 0, 100, 0, 0, 0, 0, 0], count: 100
    }]
  });
  const result = evaluateAuthRolloutSnapshots([snapshot(), slow]);
  assert.equal(result.result, 'fail');
  assert.equal(result.totals.sessionSamples, 200);
  assert.equal(result.totals.sessionP95Ms, 50);
  assert.ok(result.reasons.includes('session_p95_above_20ms'));
});

test('non-session histograms do not affect the merged session percentile', () => {
  const result = evaluateAuthRolloutSnapshots([snapshot({
    histograms: [
      ...snapshot().histograms,
      {
        metric: 'auth_session_database_seconds', dimensions: { operation: 'authenticate', outcome: 'hit' },
        unit: 'seconds', bounds: AUTH_SESSION_HISTOGRAM_BOUNDS_SECONDS,
        bucketCounts: [0, 0, 0, 0, 0, 100, 0, 0, 0, 0, 0], count: 100
      }
    ]
  })]);
  assert.equal(result.result, 'pass');
  assert.equal(result.totals.sessionSamples, 100);
  assert.equal(result.totals.sessionP95Ms, 20);
});

test('hard incidents and SLO breaches fail independently from incomplete evidence', () => {
  const result = evaluateAuthRolloutSnapshots([snapshot({
    interval: { start: new Date(start).toISOString(), end: new Date(start + 60_000).toISOString() },
    counters: [
      { metric: 'auth_oidc_callback_total', dimensions: { outcome: 'success', reason: 'none' }, value: 994 },
      { metric: 'auth_oidc_callback_total', dimensions: { outcome: 'failure', reason: 'validation' }, value: 6 }
    ],
    alerts: { crypto_integrity_failure: 1 },
    criticalIncidentCount: 1
  })]);
  assert.equal(result.result, 'fail');
  assert.ok(result.reasons.includes('critical_auth_incident'));
  assert.ok(result.reasons.includes('callback_success_below_99_5_percent'));
  assert.ok(result.reasons.includes('window_below_24h'));
});

test('coverage gaps, same-instance overlaps, and low volume are inconclusive', () => {
  const half = 12 * 60 * 60_000;
  const first = snapshot({ interval: { start: new Date(start).toISOString(), end: new Date(start + half).toISOString() } });
  const gap = snapshot({
    interval: { start: new Date(start + half + 1).toISOString(), end: new Date(start + 24 * 60 * 60_000 + 1).toISOString() },
    sequence: 2,
    counters: [],
    histograms: []
  });
  const overlap = snapshot({
    interval: { start: new Date(start + half - 1).toISOString(), end: new Date(start + 24 * 60 * 60_000).toISOString() },
    sequence: 2,
    counters: [],
    histograms: []
  });
  const gapResult = evaluateAuthRolloutSnapshots([first, gap]);
  assert.equal(gapResult.result, 'inconclusive');
  assert.ok(gapResult.reasons.includes('window_gap'));
  assert.ok(gapResult.reasons.includes('instance_interval_gap'));
  const overlapResult = evaluateAuthRolloutSnapshots([first, overlap]);
  assert.equal(overlapResult.result, 'inconclusive');
  assert.ok(overlapResult.reasons.includes('instance_interval_overlap'));
  const lowVolume = evaluateAuthRolloutSnapshots([snapshot({ counters: [], histograms: [] })]);
  assert.equal(lowVolume.result, 'inconclusive');
  assert.ok(lowVolume.reasons.includes('callback_volume_insufficient'));
  assert.ok(lowVolume.reasons.includes('session_volume_insufficient'));
});

test('snapshot dimensions are allowlisted and alert payload canaries never enter JSONL', () => {
  const canary = 'CANARY-account-tenant-session-ip-token-raw';
  const records: AuthRolloutSnapshot[] = [];
  let clock = start;
  const telemetry = createStructuredAuthTelemetry((record) => { records.push(record); }, {
    instanceId: '00000000-0000-4000-8000-000000000003', now: () => clock
  });
  telemetry.metrics.increment('auth_oidc_callback_total', { outcome: canary, reason: canary });
  telemetry.metrics.observe('auth_session_lookup_seconds', 0.01, { operation: canary, outcome: canary, account: canary });
  telemetry.alerts.emit('crypto_integrity_failure', { accountId: canary, token: canary, arbitrary: canary });
  clock += 60_000;
  telemetry.flush();
  const encoded = JSON.stringify(records);
  assert.equal(encoded.includes(canary), false);
  assert.match(encoded, /"other"/);
  assert.equal(records[0].criticalIncidentCount, 1);
  assert.ok(evaluateAuthRolloutSnapshots(records).reasons.includes('unexpected_dimension'));
});

test('all incident and SLO routes are represented by bounded alert counters', () => {
  const records: AuthRolloutSnapshot[] = [];
  let clock = start;
  const telemetry = createStructuredAuthTelemetry((record) => { records.push(record); }, {
    instanceId: '00000000-0000-4000-8000-000000000004', now: () => clock
  });
  for (const type of ['crypto_integrity_failure', 'crypto_key_failure', 'oidc_replay_or_state_miss',
    'oidc_issuer_mixup', 'rate_limit_repeated_excess'] as const) telemetry.alerts.emit(type, { unsafe: 'ignored' });
  for (let index = 0; index < 100; index += 1) {
    telemetry.metrics.increment('auth_oidc_callback_total', { outcome: 'failure', reason: 'validation' });
    telemetry.metrics.observe('auth_session_lookup_seconds', 0.05, { operation: 'authenticate', outcome: 'hit' });
  }
  clock += 60_000;
  telemetry.flush();
  assert.deepEqual(Object.keys(records[0].alerts).sort(), [
    'crypto_integrity_failure', 'crypto_key_failure', 'oidc_callback_success_slo', 'oidc_issuer_mixup',
    'oidc_replay_or_state_miss', 'rate_limit_repeated_excess', 'session_lookup_latency_slo'
  ]);
  assert.equal(records[0].criticalIncidentCount, 4);
});

test('throwing, rejecting, and slow sinks never throw and produce later gap evidence', async () => {
  let clock = start;
  const recovered: AuthRolloutSnapshot[] = [];
  let calls = 0;
  const sink: AuthSnapshotSink = (record) => {
    calls += 1;
    if (calls === 1) throw new Error('sink throw');
    if (calls === 2) return Promise.reject(new Error('sink reject'));
    recovered.push(record);
  };
  const telemetry = createStructuredAuthTelemetry(sink, {
    instanceId: '00000000-0000-4000-8000-000000000005', now: () => clock, sinkTimeoutMs: 5
  });
  clock += 1_000;
  assert.doesNotThrow(() => telemetry.flush());
  clock += 1_000;
  assert.doesNotThrow(() => telemetry.flush());
  await new Promise((resolve) => setImmediate(resolve));
  clock += 1_000;
  telemetry.flush();
  assert.deepEqual(recovered[0].observability.gaps.map((gap) => gap.code).sort(), ['sink_rejected', 'sink_throw']);

  const slowRecords: AuthRolloutSnapshot[] = [];
  let release: (() => void) | undefined;
  const slow = createStructuredAuthTelemetry((record) => {
    slowRecords.push(record);
    return new Promise<void>((resolve) => { release = resolve; });
  }, { instanceId: '00000000-0000-4000-8000-000000000006', now: () => clock, sinkTimeoutMs: 5 });
  clock += 1_000;
  slow.flush();
  await new Promise((resolve) => setTimeout(resolve, 10));
  clock += 1_000;
  slow.flush();
  assert.equal(slowRecords[1].observability.gaps[0].code, 'sink_timeout');
  release?.();
});

test('instance identity and wall-clock anomalies cannot become valid evidence', () => {
  assert.throws(() => createStructuredAuthTelemetry(() => {}, { instanceId: 'account-or-hostname' }), /UUID v4/);
  const records: AuthRolloutSnapshot[] = [];
  const telemetry = createStructuredAuthTelemetry((record) => { records.push(record); }, {
    instanceId: '00000000-0000-4000-8000-000000000007', now: () => start
  });
  telemetry.flush();
  assert.equal(records[0].observability.gaps[0].code, 'clock_anomaly');
  assert.equal(evaluateAuthRolloutSnapshots(records).result, 'inconclusive');
});
