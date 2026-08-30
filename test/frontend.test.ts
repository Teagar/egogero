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

test('app shell uses the authoritative viewport breakpoints instead of querying itself', async () => {
  const css = await readFile(new URL('../web/src/styles.css', import.meta.url), 'utf8');
  assert.doesNotMatch(css, /@container\s*\(max-width:/);
  assert.match(css, /@media\s*\(max-width:\s*900px\)\s*\{[\s\S]*?\.shell\s*\{\s*display:\s*block/);
  assert.match(css, /@media\s*\(max-width:\s*900px\)\s*\{[\s\S]*?\.sidebar\s*\{\s*display:\s*none/);
  assert.match(css, /@media\s*\(max-width:\s*900px\)\s*\{[\s\S]*?\.mobile-nav\s*\{[\s\S]*?display:\s*grid/);
  assert.match(css, /@media\s*\(max-width:\s*640px\)\s*\{[\s\S]*?\.split\s*\{\s*grid-template-columns:\s*minmax\(0, 1fr\)/);
  assert.match(css, /@media\s*\(prefers-reduced-motion:\s*reduce\)/);
});

test('frontend foundation tracks REV. 07 tokens, fonts, brand, and light theme decision', async () => {
  const [css, main, app, html, mark] = await Promise.all([
    readFile(new URL('../web/src/styles.css', import.meta.url), 'utf8'),
    readFile(new URL('../web/src/main.tsx', import.meta.url), 'utf8'),
    readFile(new URL('../web/src/App.tsx', import.meta.url), 'utf8'),
    readFile(new URL('../web/index.html', import.meta.url), 'utf8'),
    readFile(new URL('../web/src/assets/brand-mark.svg', import.meta.url), 'utf8')
  ]);

  const requiredTokens = [
    '--charcoal: #2b2a28', '--paper: #f0f1f3', '--signal: #ff6700',
    '--blueprint: #1f4b8c', '--steel: #585c63', '--success: #1f7a52',
    '--warning: #a66a00', '--danger: #b8352a', '--s-1: 8px',
    '--s-8: 128px', '--r-sm: 2px', '--r-md: 4px'
  ];
  for (const token of requiredTokens) assert.ok(css.includes(token), `missing ${token}`);

  assert.match(main, /big-shoulders-display\/latin-800/);
  assert.match(main, /public-sans\/latin-400/);
  assert.match(main, /public-sans\/latin-700/);
  assert.match(main, /ibm-plex-mono\/latin-500/);
  assert.match(main, /ibm-plex-mono\/latin-600/);
  assert.match(app, /import brandMark from '\.\/assets\/brand-mark\.svg\?no-inline'/);
  assert.match(app, /<img src=\{brandMark\} alt="" \/>/);
  assert.match(mark, /<svg[\s\S]*<title[^>]*>Marca Teagar<\/title>/);
  assert.match(html, /<meta name="color-scheme" content="light" \/>/);
  assert.match(css, /color-scheme:\s*light/);
  assert.doesNotMatch(css, /data-theme|box-shadow/);
});
