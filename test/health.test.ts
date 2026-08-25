import assert from 'node:assert/strict';
import test from 'node:test';

import { createApp } from '../src/app.js';

test('GET /health returns ok', async () => {
  const app = createApp();
  const response = await app.inject({ method: 'GET', url: '/health' });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.json(), { status: 'ok' });

  await app.close();
});

test('readiness checks the database and reports only generic state', async () => {
  let databaseAvailable = true;
  const app = createApp({
    readiness: {
      humanAuthEnabled: false,
      oidcMetadataValidated: true,
      requiredServicesComposed: true,
      async checkDatabase() {
        if (!databaseAvailable) throw new Error('postgresql://user:secret@database/private');
      }
    }
  });

  const ready = await app.inject({ method: 'GET', url: '/ready' });
  assert.equal(ready.statusCode, 200);
  assert.deepEqual(ready.json(), { status: 'ready' });

  databaseAvailable = false;
  const unavailable = await app.inject({ method: 'GET', url: '/ready' });
  assert.equal(unavailable.statusCode, 503);
  assert.deepEqual(unavailable.json(), { status: 'unavailable' });
  assert.doesNotMatch(unavailable.body, /secret|postgres|database/i);
  await app.close();
});

test('human-auth readiness requires cached OIDC validation and complete composition without provider calls', async () => {
  let databaseChecks = 0;
  const readiness = {
    humanAuthEnabled: true,
    oidcMetadataValidated: false,
    requiredServicesComposed: true,
    async checkDatabase() { databaseChecks += 1; }
  };
  const app = createApp({ readiness });

  assert.equal((await app.inject({ method: 'GET', url: '/ready' })).statusCode, 503);
  assert.equal(databaseChecks, 0);
  readiness.oidcMetadataValidated = true;
  readiness.requiredServicesComposed = false;
  assert.equal((await app.inject({ method: 'GET', url: '/ready' })).statusCode, 503);
  readiness.requiredServicesComposed = true;
  assert.equal((await app.inject({ method: 'GET', url: '/ready' })).statusCode, 200);
  assert.equal(databaseChecks, 1);
  await app.close();
});
