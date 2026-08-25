import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { appendFile, chmod, mkdir, mkdtemp, readFile, rename, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

import {
  AUTH_ROLLOUT_CONTRACT,
  AUTH_ROLLOUT_INVENTORY_CONTRACT,
  AUTH_SESSION_HISTOGRAM_BOUNDS_SECONDS,
  evaluateAuthRolloutSnapshots,
  readAuthRolloutJsonl,
  readAuthRolloutInventory,
  type AuthRolloutInventory,
  type AuthRolloutSnapshot
} from '../src/auth-rollout.js';
import {
  combineAuthAlertSinks,
  createAuthSnapshotFileSink,
  createAuthSnapshotStdoutSink,
  createRoutedAuthAlertSink,
  createStructuredAuthTelemetry,
  DEFAULT_AUTH_ALERT_ROUTES,
  prepareAuthSnapshotFile,
  type AuthAlertDelivery,
  type AuthSnapshotSink
} from '../src/auth-observability.js';
import { AUTH_ALERT_SMOKE_CONTRACT, runAuthAlertSmoke } from '../src/auth-alert-smoke.js';

const start = Date.parse('2026-08-01T00:00:00.000Z');

function snapshot(overrides: Partial<AuthRolloutSnapshot> = {}): AuthRolloutSnapshot {
  const buckets = [0, 0, 0, 0, 95, 5, 0, 0, 0, 0, 0];
  return {
    contract: AUTH_ROLLOUT_CONTRACT,
    interval: { start: new Date(start).toISOString(), end: new Date(start + 24 * 60 * 60_000).toISOString() },
    stageId: 'staging:pc-37', instanceId: '00000000-0000-4000-8000-000000000001',
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

function inventory(instances: AuthRolloutInventory['servingInstances'] = [{
  instanceId: '00000000-0000-4000-8000-000000000001',
  expectedStart: new Date(start).toISOString(),
  expectedEnd: new Date(start + 24 * 60 * 60_000).toISOString(),
  cadenceMs: 24 * 60 * 60_000
}]): AuthRolloutInventory {
  return { contract: AUTH_ROLLOUT_INVENTORY_CONTRACT, stageId: 'staging:pc-37', servingInstances: instances };
}

test('rollout evaluator passes exact callback, latency, and 24 hour boundaries', () => {
  const result = evaluateAuthRolloutSnapshots([snapshot()], inventory());
  assert.equal(result.result, 'pass');
  assert.equal(result.totals.callbackSuccessPermille, 995);
  assert.equal(result.totals.sessionP95Ms, 20);
  assert.equal(result.window.durationMs, 24 * 60 * 60_000);
});

test('rollout evaluator cannot pass without valid independent inventory or declared cadence', () => {
  assert.equal(evaluateAuthRolloutSnapshots([snapshot()]).result, 'inconclusive');
  const tooSparse = evaluateAuthRolloutSnapshots([snapshot()], inventory([{
    ...inventory().servingInstances[0], cadenceMs: 60_000
  }]));
  assert.equal(tooSparse.result, 'inconclusive');
  assert.ok(tooSparse.reasons.includes('instance_cadence_exceeded'));
  assert.ok(evaluateAuthRolloutSnapshots([
    snapshot({ stageId: 'staging:non-canary' })
  ], { ...inventory(), stageId: 'staging:non-canary' }).reasons.includes('invalid_snapshot'));
});

test('rollout evaluator rejects stage mixing and excludes foreign-stage totals', () => {
  const foreign = snapshot({
    stageId: 'production:other', alerts: { cross_tenant_access_denied: 1 }, criticalIncidentCount: 1
  });
  const result = evaluateAuthRolloutSnapshots([snapshot(), foreign], inventory());
  assert.equal(result.result, 'inconclusive');
  assert.equal(result.stageId, 'staging:pc-37');
  assert.equal(result.totals.criticalIncidents, 0);
  assert.ok(result.reasons.includes('stage_mismatch'));
});

test('rollout evaluator aggregates concurrent instances without averaging percentiles', () => {
  const slow = snapshot({
    stageId: 'staging:pc-37', instanceId: '00000000-0000-4000-8000-000000000002',
    counters: [{ metric: 'auth_oidc_callback_total', dimensions: { outcome: 'success', reason: 'none' }, value: 200 }],
    histograms: [{
      metric: 'auth_session_lookup_seconds', dimensions: { operation: 'inspect', outcome: 'hit' }, unit: 'seconds',
      bounds: AUTH_SESSION_HISTOGRAM_BOUNDS_SECONDS, bucketCounts: [0, 0, 0, 0, 0, 100, 0, 0, 0, 0, 0], count: 100
    }]
  });
  const result = evaluateAuthRolloutSnapshots([snapshot(), slow], inventory([
    ...inventory().servingInstances,
    {
      instanceId: slow.instanceId, expectedStart: slow.interval.start, expectedEnd: slow.interval.end,
      cadenceMs: 24 * 60 * 60_000
    }
  ]));
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
  })], inventory());
  assert.equal(result.result, 'pass');
  assert.equal(result.totals.sessionSamples, 100);
  assert.equal(result.totals.sessionP95Ms, 20);
});

test('hard incidents and SLO breaches fail independently from incomplete evidence', () => {
  const shortEnd = new Date(start + 60_000).toISOString();
  const result = evaluateAuthRolloutSnapshots([snapshot({
    interval: { start: new Date(start).toISOString(), end: new Date(start + 60_000).toISOString() },
    counters: [
      { metric: 'auth_oidc_callback_total', dimensions: { outcome: 'success', reason: 'none' }, value: 994 },
      { metric: 'auth_oidc_callback_total', dimensions: { outcome: 'failure', reason: 'validation' }, value: 6 }
    ],
    alerts: { crypto_integrity_failure: 1 },
    criticalIncidentCount: 1
  })], inventory([{
    instanceId: '00000000-0000-4000-8000-000000000001', expectedStart: new Date(start).toISOString(),
    expectedEnd: shortEnd, cadenceMs: 60_000
  }]));
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
  const gapResult = evaluateAuthRolloutSnapshots([first, gap], inventory());
  assert.equal(gapResult.result, 'inconclusive');
  assert.ok(gapResult.reasons.includes('expected_instance_interval_missing'));
  assert.ok(gapResult.reasons.includes('instance_interval_gap'));
  const overlapResult = evaluateAuthRolloutSnapshots([first, overlap], inventory());
  assert.equal(overlapResult.result, 'inconclusive');
  assert.ok(overlapResult.reasons.includes('instance_interval_overlap'));
  const lowVolume = evaluateAuthRolloutSnapshots([snapshot({ counters: [], histograms: [] })], inventory());
  assert.equal(lowVolume.result, 'inconclusive');
  assert.ok(lowVolume.reasons.includes('callback_volume_insufficient'));
  assert.ok(lowVolume.reasons.includes('session_volume_insufficient'));
});

test('snapshot dimensions are allowlisted and alert payload canaries never enter JSONL', () => {
  const canary = 'CANARY-account-tenant-session-ip-token-raw';
  const records: AuthRolloutSnapshot[] = [];
  let clock = start;
  const telemetry = createStructuredAuthTelemetry((record) => { records.push(record); }, {
    stageId: 'staging:pc-37', instanceId: '00000000-0000-4000-8000-000000000003', now: () => clock
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
  assert.ok(evaluateAuthRolloutSnapshots(records, inventory([{
    instanceId: records[0].instanceId, expectedStart: records[0].interval.start,
    expectedEnd: records[0].interval.end, cadenceMs: 60_000
  }])).reasons.includes('unexpected_dimension'));
  assert.equal(records[0].contract, AUTH_ROLLOUT_CONTRACT);
  assert.equal(records[0].stageId, 'staging:pc-37');
});

test('all incident and SLO routes are represented by bounded alert counters', () => {
  const records: AuthRolloutSnapshot[] = [];
  let clock = start;
  const telemetry = createStructuredAuthTelemetry((record) => { records.push(record); }, {
    stageId: 'staging:pc-37', instanceId: '00000000-0000-4000-8000-000000000004', now: () => clock
  });
  for (const type of Object.keys(DEFAULT_AUTH_ALERT_ROUTES) as Array<keyof typeof DEFAULT_AUTH_ALERT_ROUTES>) {
    telemetry.alerts.emit(type, { unsafe: 'ignored' });
  }
  for (let index = 0; index < 100; index += 1) {
    telemetry.metrics.increment('auth_oidc_callback_total', { outcome: 'failure', reason: 'validation' });
    telemetry.metrics.observe('auth_session_lookup_seconds', 0.05, { operation: 'authenticate', outcome: 'hit' });
  }
  clock += 60_000;
  telemetry.flush();
  assert.deepEqual(Object.keys(records[0].alerts).sort(), [
    'cross_tenant_access_denied',
    'crypto_integrity_failure', 'crypto_key_failure', 'oidc_callback_success_slo', 'oidc_issuer_mixup',
    'oidc_replay_or_state_miss', 'provider_configuration_drift', 'rate_limit_repeated_excess',
    'session_lookup_latency_slo', 'session_revocation_slo', 'unusual_session_creation'
  ]);
  assert.equal(records[0].criticalIncidentCount, 8);
});

test('throwing and rejecting snapshot sinks recover with explicit gap evidence', async () => {
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
    stageId: 'staging:pc-37', instanceId: '00000000-0000-4000-8000-000000000005', now: () => clock, sinkTimeoutMs: 5
  });
  clock += 1_000;
  assert.doesNotThrow(() => telemetry.flush());
  clock += 1_000;
  assert.doesNotThrow(() => telemetry.flush());
  await new Promise((resolve) => setImmediate(resolve));
  clock += 1_000;
  telemetry.flush();
  assert.deepEqual(recovered[0].observability.gaps.map((gap) => gap.code).sort(), ['sink_rejected', 'sink_throw']);

});

test('never-settling snapshot writes keep one active and one pending operation', async () => {
  let wall = start;
  let monotonic = 0;
  let calls = 0;
  const telemetry = createStructuredAuthTelemetry(() => {
    calls += 1;
    return new Promise<void>(() => {});
  }, {
    stageId: 'staging:pc-37', instanceId: '00000000-0000-4000-8000-000000000006', now: () => wall,
    monotonicNow: () => monotonic, sinkTimeoutMs: 5
  });
  for (let index = 0; index < 100; index += 1) {
    wall += 1_000;
    monotonic += 1_000;
    assert.doesNotThrow(() => telemetry.metrics.increment('auth_oidc_callback_total', { outcome: 'success', reason: 'none' }));
    assert.doesNotThrow(() => telemetry.flush());
  }
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.equal(calls, 1);
  assert.deepEqual(telemetry.sinkState(), { inFlight: true, pending: 1 });

  class BackpressuredStream extends EventEmitter {
    write() { return false; }
  }
  const stream = new BackpressuredStream();
  const stdoutTelemetry = createStructuredAuthTelemetry(createAuthSnapshotStdoutSink(stream as unknown as NodeJS.WriteStream), {
    stageId: 'staging:pc-37', instanceId: '00000000-0000-4000-8000-000000000008', now: () => wall,
    monotonicNow: () => monotonic, sinkTimeoutMs: 5
  });
  for (let index = 0; index < 100; index += 1) {
    wall += 1_000;
    monotonic += 1_000;
    stdoutTelemetry.flush();
  }
  assert.equal(stream.listenerCount('drain'), 1);
  assert.deepEqual(stdoutTelemetry.sinkState(), { inFlight: true, pending: 1 });
});

test('instance identity and wall-clock anomalies cannot become valid evidence', () => {
  assert.throws(() => createStructuredAuthTelemetry(() => {}, {
    instanceId: 'account-or-hostname', stageId: 'staging:test'
  }), /UUID v4/);
  const records: AuthRolloutSnapshot[] = [];
  const telemetry = createStructuredAuthTelemetry((record) => { records.push(record); }, {
    stageId: 'staging:pc-37', instanceId: '00000000-0000-4000-8000-000000000007', now: () => start
  });
  telemetry.flush();
  assert.equal(records[0].observability.gaps[0].code, 'clock_anomaly');
  assert.equal(evaluateAuthRolloutSnapshots(records, inventory([{
    instanceId: records[0].instanceId, expectedStart: records[0].interval.start,
    expectedEnd: records[0].interval.end, cadenceMs: 1_000
  }])).result, 'inconclusive');
});

test('monotonic drift prevents a 24 hour wall-clock jump from fabricating coverage', () => {
  let wall = start;
  let monotonic = 0;
  const records: AuthRolloutSnapshot[] = [];
  const telemetry = createStructuredAuthTelemetry((record) => { records.push(record); }, {
    stageId: 'staging:pc-37', instanceId: '00000000-0000-4000-8000-000000000009', now: () => wall,
    monotonicNow: () => monotonic, maxClockDriftMs: 1_000
  });
  wall += 24 * 60 * 60_000;
  monotonic += 60_000;
  telemetry.flush();
  assert.equal(Date.parse(records[0].interval.end) - Date.parse(records[0].interval.start), 60_000);
  assert.equal(records[0].observability.gaps[0].code, 'clock_drift');
  assert.notEqual(evaluateAuthRolloutSnapshots(records, inventory([{
    instanceId: records[0].instanceId, expectedStart: records[0].interval.start,
    expectedEnd: records[0].interval.end, cadenceMs: 60_000
  }])).result, 'pass');
});

test('independent serving inventory detects silent instances and accounts for planned restart', () => {
  const firstHour = snapshot({ interval: {
    start: new Date(start).toISOString(), end: new Date(start + 60 * 60_000).toISOString()
  } });
  const fullReplica = snapshot({ instanceId: '00000000-0000-4000-8000-000000000002' });
  const expectedBoth = inventory([
    ...inventory().servingInstances,
    { instanceId: fullReplica.instanceId, expectedStart: fullReplica.interval.start,
      expectedEnd: fullReplica.interval.end, cadenceMs: 24 * 60 * 60_000 }
  ]);
  const silent = evaluateAuthRolloutSnapshots([firstHour, fullReplica], expectedBoth);
  assert.equal(silent.result, 'inconclusive');
  assert.ok(silent.reasons.includes('expected_instance_interval_missing'));

  const midpoint = start + 12 * 60 * 60_000;
  const before = snapshot({ interval: { start: new Date(start).toISOString(), end: new Date(midpoint).toISOString() } });
  const after = snapshot({
    stageId: 'staging:pc-37', instanceId: '00000000-0000-4000-8000-000000000002',
    interval: { start: new Date(midpoint).toISOString(), end: new Date(start + 24 * 60 * 60_000).toISOString() },
    counters: [], histograms: []
  });
  const planned = evaluateAuthRolloutSnapshots([before, after], inventory([
    { instanceId: before.instanceId, expectedStart: before.interval.start, expectedEnd: before.interval.end,
      cadenceMs: 12 * 60 * 60_000 },
    { instanceId: after.instanceId, expectedStart: after.interval.start, expectedEnd: after.interval.end,
      cadenceMs: 12 * 60 * 60_000 }
  ]));
  assert.equal(planned.result, 'pass');
});

test('alert routing delivers only bounded routes and reports nonblocking failures', async () => {
  const delivered: AuthAlertDelivery[] = [];
  const gaps: string[] = [];
  const routing = createRoutedAuthAlertSink(DEFAULT_AUTH_ALERT_ROUTES, async (delivery) => {
    delivered.push(delivery);
    return { acknowledged: true };
  }, { onGap: (gap) => gaps.push(gap) });
  for (const type of Object.keys(DEFAULT_AUTH_ALERT_ROUTES) as Array<keyof typeof DEFAULT_AUTH_ALERT_ROUTES>) {
    routing.sink.emit(type, { token: 'CANARY-secret', accountId: 'CANARY-account' });
    await new Promise((resolve) => setImmediate(resolve));
  }
  assert.equal(delivered.length, Object.keys(DEFAULT_AUTH_ALERT_ROUTES).length);
  assert.deepEqual(delivered.map((delivery) => delivery.routes), Object.values(DEFAULT_AUTH_ALERT_ROUTES));
  assert.equal(JSON.stringify(delivered).includes('CANARY'), false);
  assert.deepEqual(delivered.map((delivery) => delivery.routes), Object.values(DEFAULT_AUTH_ALERT_ROUTES));
  assert.deepEqual(gaps, []);

  const unacknowledged: string[] = [];
  const noAck = createRoutedAuthAlertSink(DEFAULT_AUTH_ALERT_ROUTES,
    async () => ({ acknowledged: false }), { onGap: (gap) => unacknowledged.push(gap) });
  noAck.sink.emit('oidc_callback_success_slo', {});
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(unacknowledged, ['alert_route_unacknowledged']);

  const telemetry = createStructuredAuthTelemetry(() => {}, {
    stageId: 'staging:pc-37', instanceId: '00000000-0000-4000-8000-000000000010', now: () => start
  });
  let attempts = 0;
  const failing = createRoutedAuthAlertSink(DEFAULT_AUTH_ALERT_ROUTES, () => {
    attempts += 1;
    if (attempts === 1) throw new Error('throw');
    if (attempts === 2) return Promise.reject(new Error('reject'));
    return new Promise(() => {});
  }, { timeoutMs: 5, onGap: telemetry.recordObservabilityGap });
  const combined = combineAuthAlertSinks(telemetry.alerts, failing.sink);
  assert.doesNotThrow(() => combined.emit('crypto_key_failure', { token: 'secret' }));
  combined.emit('crypto_key_failure', {});
  await new Promise((resolve) => setImmediate(resolve));
  combined.emit('crypto_key_failure', {});
  combined.emit('crypto_key_failure', {});
  combined.emit('crypto_key_failure', {});
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.deepEqual(failing.state(), { inFlight: true, pending: 1 });
  const record = telemetry.flush();
  assert.ok(record?.observability.gaps.some((gap) => gap.code === 'alert_route_throw'));
  assert.ok(record?.observability.gaps.some((gap) => gap.code === 'alert_route_rejected'));
  assert.ok(record?.observability.gaps.some((gap) => gap.code === 'alert_route_timeout'));
  assert.ok(record?.observability.gaps.some((gap) => gap.code === 'alert_route_backpressure'));
});

test('external alert smoke requires acknowledgement for every bounded route', async () => {
  const delivered: AuthAlertDelivery[] = [];
  const result = await runAuthAlertSmoke(async (delivery) => {
    delivered.push(delivery);
    return { acknowledged: true };
  }, 100);
  assert.deepEqual(result, {
    contract: AUTH_ALERT_SMOKE_CONTRACT, acknowledged: true, alertTypes: Object.keys(DEFAULT_AUTH_ALERT_ROUTES).length
  });
  assert.deepEqual(delivered.map((delivery) => delivery.type), Object.keys(DEFAULT_AUTH_ALERT_ROUTES));
  await assert.rejects(runAuthAlertSmoke(async () => ({ acknowledged: false }), 100), /not acknowledged/);
  await assert.rejects(runAuthAlertSmoke(() => new Promise(() => {}), 100), /timed out/);
});

test('streaming JSONL limits fail safely and secure file sink repairs mode and recovers', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'pc33-'));
  try {
    const oversized = path.join(root, 'oversized.jsonl');
    await writeFile(oversized, `${'x'.repeat(300 * 1_024)}\n`, 'utf8');
    await assert.rejects(readAuthRolloutJsonl([oversized], {
      files: 1, records: 1, lineBytes: 64, fileBytes: 256, totalBytes: 256, inventoryBytes: 256
    }), /limit exceeded/);
    const limited = evaluateAuthRolloutSnapshots([], inventory(), ['input_limit_exceeded']);
    assert.equal(limited.result, 'inconclusive');
    const inventoryPath = path.join(root, 'inventory.json');
    await writeFile(inventoryPath, JSON.stringify(inventory()), 'utf8');
    const command = spawnSync(process.execPath, [
      '--import', 'tsx', 'src/auth-rollout.ts', '--inventory', inventoryPath, oversized
    ], { cwd: process.cwd(), encoding: 'utf8' });
    assert.equal(command.status, 2, command.stderr);
    const output = JSON.parse(command.stdout) as { contract: string; result: string; reasons: string[] };
    assert.equal(output.result, 'inconclusive');
    assert.ok(output.reasons.includes('input_limit_exceeded'));
    assert.equal(output.contract, 'egogero.auth-rollout-evaluation/v2');

    const special = path.join(root, 'special');
    await mkdir(special);
    await assert.rejects(readAuthRolloutInventory(special), /regular file/);
    const emptySnapshots = path.join(root, 'empty.jsonl');
    await writeFile(emptySnapshots, '', 'utf8');
    const specialCommand = spawnSync(process.execPath, [
      '--import', 'tsx', 'src/auth-rollout.ts', '--inventory', special, emptySnapshots
    ], { cwd: process.cwd(), encoding: 'utf8' });
    assert.equal(specialCommand.status, 2, specialCommand.stderr);
    const specialOutput = JSON.parse(specialCommand.stdout) as { result: string; reasons: string[] };
    assert.equal(specialOutput.result, 'inconclusive');
    assert.ok(specialOutput.reasons.includes('input_limit_exceeded'));
    const link = path.join(root, 'inventory-link.json');
    await symlink(inventoryPath, link);
    await assert.rejects(readAuthRolloutInventory(link), /regular file/);
    const multiline = path.join(root, 'inventory-multiline.json');
    await writeFile(multiline, '{}\n{}\n', 'utf8');
    await assert.rejects(readAuthRolloutInventory(multiline), /exactly one JSON record/);

    const growing = path.join(root, 'inventory-growing.json');
    await writeFile(growing, JSON.stringify(inventory()), 'utf8');
    await assert.rejects(readAuthRolloutInventory(growing, {
      chunkBytes: 1,
      afterOpen: async () => { await appendFile(growing, ' '); }
    }), /changed while being read/);
    const replaced = path.join(root, 'inventory-replaced.json');
    const replacedOld = path.join(root, 'inventory-replaced-old.json');
    await writeFile(replaced, JSON.stringify(inventory()), 'utf8');
    await assert.rejects(readAuthRolloutInventory(replaced, {
      chunkBytes: 1,
      afterOpen: async () => {
        await rename(replaced, replacedOld);
        await writeFile(replaced, JSON.stringify(inventory()), 'utf8');
      }
    }), /changed while being read/);

    const snapshotLink = path.join(root, 'snapshot-link.jsonl');
    await symlink(emptySnapshots, snapshotLink);
    await assert.rejects(readAuthRolloutJsonl([snapshotLink]), /regular file/);
    const growingSnapshot = path.join(root, 'snapshot-growing.jsonl');
    await writeFile(growingSnapshot, `${JSON.stringify(snapshot())}\n`, 'utf8');
    await assert.rejects(readAuthRolloutJsonl([growingSnapshot], undefined, {
      chunkBytes: 1,
      afterOpen: async () => { await appendFile(growingSnapshot, '{}\n'); }
    }), /changed while being read/);
    const replacedSnapshot = path.join(root, 'snapshot-replaced.jsonl');
    const replacedSnapshotOld = path.join(root, 'snapshot-replaced-old.jsonl');
    await writeFile(replacedSnapshot, `${JSON.stringify(snapshot())}\n`, 'utf8');
    await assert.rejects(readAuthRolloutJsonl([replacedSnapshot], undefined, {
      chunkBytes: 1,
      afterOpen: async () => {
        await rename(replacedSnapshot, replacedSnapshotOld);
        await writeFile(replacedSnapshot, `${JSON.stringify(snapshot())}\n`, 'utf8');
      }
    }), /changed while being read/);

    const directory = path.join(root, 'later');
    const file = path.join(directory, 'snapshots.jsonl');
    const fileSink = createAuthSnapshotFileSink(file);
    await assert.rejects(fileSink(snapshot()) as Promise<void>);
    await mkdir(directory);
    await writeFile(file, '', { mode: 0o666 });
    await chmod(file, 0o666);
    await fileSink(snapshot());
    assert.equal((await stat(file)).mode & 0o777, 0o600);
    assert.match(await readFile(file, 'utf8'), /egogero\.auth-rollout\/v2/);
    await assert.rejects(createAuthSnapshotFileSink(file, { maxBytes: 1 })(snapshot()) as Promise<void>, /limit exceeded/);
    const prepared = path.join(root, 'prepared.jsonl');
    await prepareAuthSnapshotFile(prepared);
    assert.equal((await stat(prepared)).mode & 0o777, 0o600);
    const preparedLink = path.join(root, 'prepared-link.jsonl');
    await symlink(prepared, preparedLink);
    await assert.rejects(prepareAuthSnapshotFile(preparedLink));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
