import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';

import type { Reporter } from '@playwright/test/reporter';

const TEXT_ARTIFACT = /\.(?:html|json|log|md|txt)$/i;

export default class RedactingReporter implements Reporter {
  onEnd() {
    let invitationToken = '';
    try { invitationToken = readFileSync(path.resolve('.e2e-tmp/invitation-token'), 'utf8').trim(); } catch { /* no fixture */ }
    for (const root of ['test-results', 'playwright-report']) redactBelow(path.resolve(root), invitationToken);
  }
}

function redactBelow(location: string, invitationToken: string) {
  let entries;
  try { entries = readdirSync(location); } catch { return; }
  for (const entry of entries) {
    const target = path.join(location, entry);
    if (statSync(target).isDirectory()) {
      redactBelow(target, invitationToken);
      continue;
    }
    if (!TEXT_ARTIFACT.test(target)) continue;
    const original = readFileSync(target, 'utf8');
    const redacted = original
      .replace(/((?:[?&]|\\u0026)(?:code|state|nonce|token|code_verifier)=)[^&\s"'<>\\]+/gi, '$1[REDACTED]')
      .replace(/(__Host-eg_(?:session|oidc_handoff)=)[^;\s"'<>]+/gi, '$1[REDACTED]')
      .replace(/(x-csrf-token["'\s:=]+)[A-Za-z0-9_-]+/gi, '$1[REDACTED]')
      .replace(/egdev_[A-Za-z0-9_-]+/g, 'egdev_[REDACTED]')
      .replaceAll(invitationToken || '\0', '[REDACTED]');
    if (redacted !== original) writeFileSync(target, redacted, { mode: 0o600 });
  }
}
