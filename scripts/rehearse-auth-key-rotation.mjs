/* global console, process */

import { spawnSync } from 'node:child_process';

if (process.env.RUN_DATABASE_TESTS !== 'true' || !process.env.DATABASE_URL) {
  console.error('Rotation rehearsal requires RUN_DATABASE_TESTS=true and DATABASE_URL for a migrated disposable database');
  process.exitCode = 1;
} else {
  const result = spawnSync(process.execPath, [
    '--test',
    '--test-concurrency=1',
    '--test-name-pattern=rotation rehearsal|credential and webhook cutover',
    '--import',
    'tsx',
    'test/oidc.test.ts',
    'test/sessions-db.test.ts',
    'test/auth-rotation-cutover.test.ts',
    'test/deployment-config.test.ts'
  ], { stdio: 'inherit', env: process.env });
  process.exitCode = result.status ?? 1;
}
