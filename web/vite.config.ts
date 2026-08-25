import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  root: new URL('.', import.meta.url).pathname,
  plugins: [react()],
  build: { sourcemap: false },
  test: { environment: 'jsdom', include: ['src/**/*.test.ts'] }
});
