import { defineConfig } from '@playwright/test';

const evidenceRoot = '.visual-evidence';

export default defineConfig({
  testDir: './test/visual',
  testMatch: 'evidence.spec.ts',
  fullyParallel: false,
  workers: 1,
  timeout: 30_000,
  expect: { timeout: 7_500 },
  forbidOnly: Boolean(process.env.CI),
  retries: 0,
  reporter: 'line',
  outputDir: `${evidenceRoot}/results`,
  globalSetup: './test/visual/setup.ts',
  use: {
    baseURL: 'http://127.0.0.1:4173',
    browserName: 'chromium',
    colorScheme: 'light',
    locale: 'pt-BR',
    contextOptions: { reducedMotion: 'reduce' },
    trace: 'off',
    video: 'off',
    screenshot: 'off'
  },
  projects: [
    { name: 'desktop', use: { viewport: { width: 1440, height: 1000 } } },
    { name: 'tablet', use: { viewport: { width: 768, height: 1024 } } },
    { name: 'mobile', use: { viewport: { width: 390, height: 844 } } },
    { name: 'compact', use: { viewport: { width: 320, height: 720 } } }
  ],
  webServer: {
    command: 'vite preview --config web/vite.config.ts --host 127.0.0.1 --port 4173',
    url: 'http://127.0.0.1:4173',
    reuseExistingServer: false,
    timeout: 30_000,
    stdout: 'pipe',
    stderr: 'pipe'
  }
});
