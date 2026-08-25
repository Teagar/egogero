import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { createApp } from '../src/app.js';

test('frontend serves only exact documents and assets with strict security and cache policy', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'office-web-'));
  await mkdir(path.join(root, 'assets'));
  await writeFile(path.join(root, 'index.html'), '<!doctype html><title>Office</title>');
  await writeFile(path.join(root, 'assets', 'app-a1b2.js'), 'export{}');
  const app = createApp({ frontendRoot: root });
  try {
    const document = await app.inject({ method: 'GET', url: '/app' });
    assert.equal(document.statusCode, 200);
    assert.match(document.headers['content-type']!, /^text\/html/);
    assert.equal(document.headers['cache-control'], 'no-store');
    assert.match(document.headers['content-security-policy']!, /script-src 'self'/);
    assert.match(document.headers['content-security-policy']!, /frame-ancestors 'none'/);
    assert.doesNotMatch(String(document.headers['content-security-policy']), /unsafe-(?:inline|eval)/);
    assert.equal(document.headers['x-content-type-options'], 'nosniff');
    assert.equal(document.headers['referrer-policy'], 'no-referrer');
    assert.match(String(document.headers['permissions-policy']), /camera=\(\)/);

    const logoutContinuation = await app.inject({ method: 'GET', url: '/logout-all/continue' });
    assert.equal(logoutContinuation.statusCode, 200);
    assert.match(logoutContinuation.headers['content-type']!, /^text\/html/);
    assert.equal(logoutContinuation.headers['cache-control'], 'no-store');

    const asset = await app.inject({ method: 'GET', url: '/assets/app-a1b2.js' });
    assert.equal(asset.statusCode, 200);
    assert.match(asset.headers['cache-control']!, /immutable/);
    assert.equal((await app.inject({ method: 'POST', url: '/app' })).statusCode, 404);
    assert.equal((await app.inject({ method: 'GET', url: '/unknown' })).statusCode, 404);
    assert.equal((await app.inject({ method: 'GET', url: '/auth/session' })).statusCode, 404);
    assert.notEqual((await app.inject({ method: 'GET', url: '/assets/%2e%2e/index.html' })).statusCode, 200);
  } finally {
    await app.close();
    await rm(root, { recursive: true, force: true });
  }
});

test('app shell uses the authoritative viewport breakpoint instead of querying itself', async () => {
  const css = await readFile(new URL('../web/src/styles.css', import.meta.url), 'utf8');
  assert.doesNotMatch(css, /@container\s*\(max-width:\s*680px\)/);
  assert.match(css, /@media\s*\(max-width:\s*680px\)\s*\{[\s\S]*?\.shell\s*\{\s*display:\s*block/);
  assert.match(css, /@media\s*\(max-width:\s*680px\)\s*\{[\s\S]*?\.sidebar\s*\{\s*display:\s*none/);
  assert.match(css, /@media\s*\(max-width:\s*680px\)\s*\{[\s\S]*?\.mobile-nav\s*\{[\s\S]*?display:\s*grid/);
});
