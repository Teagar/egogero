import { spawn, spawnSync } from 'node:child_process';
import { access } from 'node:fs/promises';

import { chromium } from '@playwright/test';

try {
  await access(chromium.executablePath());
} catch {
  const reason = `Chromium is unavailable at ${chromium.executablePath()}; run npm run test:e2e:install`;
  if (process.env.CI) {
    process.stderr.write(`E2E REQUIRED: ${reason}\n`);
    process.exit(1);
  }
  process.stdout.write(`E2E SKIP: ${reason}\n`);
  process.exit(0);
}

const build = spawnSync('npm', ['run', 'build'], { cwd: process.cwd(), stdio: 'inherit', env: process.env });
if (build.status !== 0) process.exit(build.status ?? 1);

const child = spawn(process.execPath, [
  pathFromCwd('node_modules/@playwright/test/cli.js'), 'test', ...process.argv.slice(2)
], {
  cwd: process.cwd(), stdio: 'inherit', env: { ...process.env, PC31_E2E_BROWSER_READY: 'true' }
});
child.once('exit', (code, signal) => process.exit(signal ? 1 : code ?? 1));

function pathFromCwd(relative: string) {
  return new URL(relative, `file://${process.cwd()}/`).pathname;
}
