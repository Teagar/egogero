import assert from 'node:assert/strict';
import test from 'node:test';

import { isValidTimeZone } from '../src/timezones.js';

test('timezone validation accepts recognized slashless tzdb identifiers containing digits', () => {
  for (const timeZone of ['EST5EDT', 'CST6CDT', 'PST8PDT', 'GMT0']) {
    assert.equal(isValidTimeZone(timeZone), true, timeZone);
  }
});

test('timezone validation rejects offsets, malformed names, and lexically valid unknown identifiers', () => {
  for (const timeZone of ['', '+01:00', ' America/Sao_Paulo', 'America//Sao_Paulo', '1Invalid', 'Mars0Olympus']) {
    assert.equal(isValidTimeZone(timeZone), false, timeZone);
  }
});
