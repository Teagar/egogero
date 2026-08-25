import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';

import type { FullResult, Reporter, TestCase, TestResult } from '@playwright/test/reporter';

export default class SafeReporter implements Reporter {
  private readonly rows: Array<{ status: string; title: string }> = [];

  onTestEnd(test: TestCase, result: TestResult) {
    const title = test.titlePath().join(' > ');
    this.rows.push({ status: result.status, title });
    process.stdout.write(`${result.status.toUpperCase()} ${title}\n`);
  }

  onEnd(result: FullResult) {
    process.stdout.write(`E2E ${result.status.toUpperCase()}\n`);
    const reportRoot = path.resolve('playwright-report');
    mkdirSync(reportRoot, { recursive: true, mode: 0o700 });
    const rows = this.rows.map(({ status, title }) =>
      `<tr><td>${escapeHtml(status)}</td><td>${escapeHtml(title)}</td></tr>`).join('');
    writeFileSync(path.join(reportRoot, 'index.html'),
      `<!doctype html><meta charset="utf-8"><title>PC31 E2E</title><h1>${escapeHtml(result.status)}</h1><table>${rows}</table>`,
      { mode: 0o600 });
  }

  printsToStdio() { return true; }
}

function escapeHtml(value: string) {
  return value.replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[character]!);
}
