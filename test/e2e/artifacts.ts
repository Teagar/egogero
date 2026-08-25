import { readFile, readdir, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';

const TEXT_ARTIFACT = /\.(?:html|json|log|md|txt|xml)$/i;
const FORBIDDEN_CAPTURE = /\.(?:png|jpe?g|webm|zip|trace)$/i;
const QUERY_SECRET = /((?:[?&]|\\u0026)(?:code|state|nonce|token|code_verifier)=)[^&\s"'<>\\]+/gi;
const COOKIE_SECRET = /(__Host-eg_(?:session|oidc_handoff)=)[^;\s"'<>]+/gi;
const CSRF_SECRET = /(x-csrf-token["'\s:=]+)[A-Za-z0-9_-]+/gi;
const DEVICE_SECRET = /egdev_[A-Za-z0-9_-]+/g;
const OPAQUE_SECRET = /(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])/g;
const FINAL_SECRET = /(?:[?&](?:code|state|nonce|token|code_verifier)=[^&\s"'<>]+|__Host-eg_(?:session|oidc_handoff)=[^;\s"'<>]+|x-csrf-token["'\s:=]+[A-Za-z0-9_-]+|egdev_[A-Za-z0-9_-]+)/i;

export const ARTIFACT_CANARY = 'pc31-artifact-secret-canary';

export async function sanitizeAndVerifyArtifacts(extraSecrets: readonly string[] = []) {
  const roots = ['test-results', 'playwright-report'].map((root) => path.resolve(root));
  const files = (await Promise.all(roots.map(filesBelow))).flat();
  for (const file of files) {
    if (FORBIDDEN_CAPTURE.test(file)) {
      await rm(file, { force: true });
      throw new Error(`Forbidden binary browser artifact: ${path.relative(process.cwd(), file)}`);
    }
    const original = await readFile(file);
    if (TEXT_ARTIFACT.test(file)) {
      let redacted = original.toString('utf8')
        .replace(QUERY_SECRET, '$1[REDACTED]')
        .replace(COOKIE_SECRET, '$1[REDACTED]')
        .replace(CSRF_SECRET, '$1[REDACTED]')
        .replace(DEVICE_SECRET, 'egdev_[REDACTED]')
        .replace(OPAQUE_SECRET, '[REDACTED]');
      for (const secret of [ARTIFACT_CANARY, ...extraSecrets]) {
        if (secret) redacted = redacted.replaceAll(secret, '[REDACTED]');
      }
      if (redacted !== original.toString('utf8')) await writeFile(file, redacted, { mode: 0o600 });
    }
  }

  const remaining = (await Promise.all(roots.map(filesBelow))).flat();
  for (const file of remaining) {
    const bytes = await readFile(file);
    const content = bytes.toString('latin1');
    if (hasCredentialLeak(content, extraSecrets)) {
      await rm(file, { force: true });
      throw new Error(`Artifact credential scan failed for ${path.relative(process.cwd(), file)}`);
    }
  }
}

export function hasCredentialLeak(content: string, extraSecrets: readonly string[] = []) {
  const knownLeak = [ARTIFACT_CANARY, ...extraSecrets].some((secret) => secret && content.includes(secret));
  // A quote terminates every credential pattern without joining punctuation onto an empty value.
  const withoutMarkers = content.replaceAll('[REDACTED]', '"');
  return Boolean(knownLeak || FINAL_SECRET.test(withoutMarkers));
}

async function filesBelow(root: string): Promise<string[]> {
  let entries;
  try { entries = await readdir(root, { withFileTypes: true }); } catch { return []; }
  return (await Promise.all(entries.map((entry) => {
    const location = path.join(root, entry.name);
    return entry.isDirectory() ? filesBelow(location) : [location];
  }))).flat();
}
