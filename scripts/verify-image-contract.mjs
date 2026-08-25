/* global console, process */

import { spawnSync } from 'node:child_process';

const image = process.argv[2];
if (!image) throw new Error('Usage: node scripts/verify-image-contract.mjs IMAGE');

function run(args) {
  const result = spawnSync('docker', args, { encoding: 'utf8' });
  if (result.status !== 0) throw new Error(result.stderr.trim() || 'Docker image contract command failed');
  return result.stdout.trim();
}

if (run(['image', 'inspect', image, '--format', '{{.Config.User}}']) !== 'node') {
  throw new Error('Image Config.User must be node');
}

const inspection = run([
  'run', '--rm', '--read-only', '--tmpfs', '/tmp', '--entrypoint', 'node', image, '-e', `
    const fs = require('node:fs');
    const path = require('node:path');
    const required = ['/app/dist/src/server.js', '/app/web/dist/index.html', '/app/prisma/schema.prisma'];
    const failures = [];
    function walk(entry) {
      const stat = fs.lstatSync(entry);
      if (stat.uid !== 0 || stat.gid !== 0) failures.push('non-root-owned:' + entry);
      if (!stat.isSymbolicLink() && (stat.mode & 0o222) !== 0) failures.push('writable:' + entry);
      if (/^\\.env(?:\\.|$)/.test(path.basename(entry))) failures.push('environment-file:' + entry);
      if (stat.isDirectory()) for (const child of fs.readdirSync(entry)) walk(path.join(entry, child));
    }
    walk('/app');
    for (const entry of required) if (!fs.existsSync(entry)) failures.push('missing:' + entry);
    if (process.getuid() !== 1000 || process.getgid() !== 1000) failures.push('runtime-identity');
    if (failures.length) throw new Error(failures.join(','));
    console.log(JSON.stringify({ uid: process.getuid(), gid: process.getgid(), rootOwnedReadOnly: true, assets: true }));
  `
]);
console.log(inspection);
