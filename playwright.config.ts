import { defineConfig, devices } from '@playwright/test';

const appOrigin = 'https://127.0.0.1:3443';

export default defineConfig({
  testDir: './test/e2e',
  testMatch: '*.spec.ts',
  fullyParallel: false,
  workers: 1,
  timeout: 30_000,
  expect: { timeout: 7_500 },
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI
    ? [['./test/e2e/redacting-reporter.ts'], ['line'], ['html', { open: 'never' }]]
    : [['./test/e2e/redacting-reporter.ts'], ['line']],
  outputDir: 'test-results',
  use: {
    baseURL: appOrigin,
    ignoreHTTPSErrors: true,
    trace: 'off',
    video: 'off',
    screenshot: 'only-on-failure'
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } }
  ],
  webServer: {
    command: 'node --import tsx test/e2e/harness.ts',
    url: `${appOrigin}/health`,
    ignoreHTTPSErrors: true,
    reuseExistingServer: false,
    timeout: 90_000,
    stdout: 'pipe',
    stderr: 'pipe'
  }
});
