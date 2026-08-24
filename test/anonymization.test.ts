import assert from 'node:assert/strict';
import test from 'node:test';

import { anonymizationConfig, subtractUtcMonths } from '../src/jobs/anonymize-old-guests.js';

test('anonymization retention uses bounded calendar-month configuration', () => {
  assert.deepEqual(anonymizationConfig({}), { retentionMonths: 12, batchSize: 500 });
  assert.deepEqual(anonymizationConfig({
    ANONYMIZATION_RETENTION_MONTHS: '18',
    ANONYMIZATION_BATCH_SIZE: '1000'
  }), { retentionMonths: 18, batchSize: 1000 });
  assert.throws(() => anonymizationConfig({ ANONYMIZATION_RETENTION_MONTHS: '0' }), /between 1 and 120/);
  assert.throws(() => anonymizationConfig({ ANONYMIZATION_BATCH_SIZE: '1001' }), /between 1 and 1000/);
});

test('calendar-month subtraction clamps month-end without changing UTC time', () => {
  assert.equal(
    subtractUtcMonths(new Date('2026-03-31T18:20:30.123Z'), 1).toISOString(),
    '2026-02-28T18:20:30.123Z'
  );
  assert.equal(
    subtractUtcMonths(new Date('2024-03-31T18:20:30.123Z'), 1).toISOString(),
    '2024-02-29T18:20:30.123Z'
  );
});
