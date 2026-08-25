import { readFileSync } from 'node:fs';
import path from 'node:path';

import { defineConfig, devices } from '@playwright/test';

const appOrigin = 'https://127.0.0.1:3443';
const trustedSpki = readFileSync(path.resolve('.e2e-tmp/trusted-spki'), 'utf8').trim();

export default defineConfig({
  testDir: './test/e2e',
  testMatch: '*.spec.ts',
  fullyParallel: false,
  workers: 1,
  timeout: 30_000,
  expect: { timeout: 7_500 },
  forbidOnly: Boolean(process.env.CI),
  retries: 0,
  reporter: [['./test/e2e/safe-reporter.ts']],
  outputDir: 'test-results',
  use: {
    baseURL: appOrigin,
    trace: 'off',
    video: 'off',
    screenshot: 'off',
    launchOptions: { args: [`--ignore-certificate-errors-spki-list=${trustedSpki}`] }
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } }
  ],
  webServer: {
    command: 'node --import tsx test/e2e/harness.ts',
    url: 'http://127.0.0.1:3442/health',
    reuseExistingServer: false,
    timeout: 90_000,
    stdout: 'pipe',
    stderr: 'pipe'
  }
});
