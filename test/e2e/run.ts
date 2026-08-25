import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { createHash, X509Certificate } from 'node:crypto';
import { access, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { chromium } from '@playwright/test';

import { sanitizeAndVerifyArtifacts } from './artifacts.js';

const tempRoot = path.resolve('.e2e-tmp');

if (process.env.CI && process.env.ALLOW_E2E_SKIP === 'true') {
  process.stderr.write('E2E REQUIRED: ALLOW_E2E_SKIP is forbidden in CI\n');
  process.exit(1);
}

try {
  await access(chromium.executablePath());
} catch {
  const reason = `Chromium is unavailable at ${chromium.executablePath()}; run npm run test:e2e:install`;
  if (process.env.ALLOW_E2E_SKIP === 'true' && !process.env.CI) {
    process.stdout.write(`E2E SKIP: ${reason}\n`);
    process.exit(0);
  }
  process.stderr.write(`E2E REQUIRED: ${reason}; set ALLOW_E2E_SKIP=true only for an explicit local skip\n`);
  process.exit(1);
}

const build = spawnSync('npm', ['run', 'build'], { cwd: process.cwd(), stdio: 'inherit', env: process.env });
if (build.status !== 0) process.exit(build.status ?? 1);

let playwright: ChildProcess | undefined;
let exitCode = 1;
let interrupted = false;
const interrupt = () => {
  interrupted = true;
  if (playwright?.exitCode === null) playwright.kill('SIGTERM');
};
process.once('SIGTERM', interrupt);
process.once('SIGINT', interrupt);
try {
  await rm(tempRoot, { recursive: true, force: true });
  await Promise.all(['test-results', 'playwright-report'].map((root) => rm(path.resolve(root), { recursive: true, force: true })));
  await mkdir(tempRoot, { recursive: true, mode: 0o700 });
  const certPath = await createCertificate('trusted');
  await createCertificate('untrusted');
  const certificate = new X509Certificate(await readFile(certPath));
  const spki = createHash('sha256').update(certificate.publicKey.export({ type: 'spki', format: 'der' })).digest('base64');
  await writeFile(path.join(tempRoot, 'trusted-spki'), spki, { mode: 0o600 });

  playwright = spawn(process.execPath, [
    path.resolve('node_modules/@playwright/test/cli.js'), 'test', ...process.argv.slice(2)
  ], {
    cwd: process.cwd(), stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      ...process.env, NODE_EXTRA_CA_CERTS: certPath, PC31_E2E_BROWSER_READY: 'true'
    }
  });
  pipeSanitized(playwright.stdout, process.stdout);
  pipeSanitized(playwright.stderr, process.stderr);
  exitCode = await childExit(playwright);
  if (interrupted) exitCode = 1;

  let invitationToken = '';
  try { invitationToken = (await readFile(path.join(tempRoot, 'invitation-token'), 'utf8')).trim(); } catch { /* setup failed */ }
  await sanitizeAndVerifyArtifacts([invitationToken]);
} catch (error) {
  process.stderr.write(`${redact(error instanceof Error ? error.message : String(error))}\n`);
  exitCode = 1;
} finally {
  process.removeListener('SIGTERM', interrupt);
  process.removeListener('SIGINT', interrupt);
  if (playwright && playwright.exitCode === null) await terminate(playwright);
  await rm(tempRoot, { recursive: true, force: true });
}

process.exit(exitCode);

async function createCertificate(name: string) {
  const keyPath = path.join(tempRoot, `${name}-key.pem`);
  const certPath = path.join(tempRoot, `${name}-cert.pem`);
  const generated = spawnSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-days', '1',
    '-subj', `/CN=${name}.pc31.local`, '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
    '-addext', 'basicConstraints=critical,CA:FALSE', '-keyout', keyPath, '-out', certPath
  ], { encoding: 'utf8' });
  if (generated.status !== 0) throw new Error(`Certificate generation failed: ${redact(generated.stderr)}`);
  return certPath;
}

function redact(value: string) {
  return value
    .replace(/(authorization:\s*(?:basic|bearer)\s+)[^\s]+/gi, '$1[REDACTED]')
    .replace(/(__Host-eg_(?:session|oidc_handoff)=)[^;\s]+/gi, '$1[REDACTED]')
    .replace(/([?&](?:code|state|nonce|token|code_verifier)=)[^&\s]+/gi, '$1[REDACTED]')
    .replace(/(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])/g, '[REDACTED]')
    .replace(/egdev_[A-Za-z0-9_-]+/g, 'egdev_[REDACTED]');
}

function pipeSanitized(input: NodeJS.ReadableStream | null, output: NodeJS.WritableStream) {
  if (!input) return;
  let pending = '';
  input.setEncoding('utf8');
  input.on('data', (chunk: string) => {
    pending += chunk;
    const lines = pending.split('\n');
    pending = lines.pop() ?? '';
    for (const line of lines) output.write(`${redact(line)}\n`);
  });
  input.on('end', () => { if (pending) output.write(redact(pending)); });
}

function childExit(child: ChildProcess) {
  return new Promise<number>((resolve) => child.once('exit', (code, signal) => resolve(signal ? 1 : code ?? 1)));
}

async function terminate(child: ChildProcess) {
  child.kill('SIGTERM');
  const exited = childExit(child);
  const graceful = await Promise.race([exited.then(() => true), new Promise<false>((resolve) => setTimeout(() => resolve(false), 3_000))]);
  if (!graceful && child.exitCode === null) {
    child.kill('SIGKILL');
    await childExit(child);
  }
}
