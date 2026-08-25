/* global console, process */

const options = Object.fromEntries(process.argv.slice(2).map((argument) => {
  const [name, value] = argument.replace(/^--/, '').split('=', 2);
  return [name, value];
}));

if (!['pkce', 'csrf'].includes(options.kind) || !['prepare', 'retire', 'compromised'].includes(options.action)) {
  throw new Error('Usage: --kind=pkce|csrf --action=prepare|retire|compromised --current=N --versions=N[,N]');
}
const current = Number(options.current);
const versions = (options.versions ?? '').split(',').filter(Boolean).map(Number);
if (!Number.isSafeInteger(current) || current < 1 || versions.some((version) => !Number.isSafeInteger(version))) {
  throw new Error('Versions must be positive integers');
}
const unique = new Set(versions);
if (unique.size !== versions.length || !unique.has(current) || versions.length < 1 || versions.length > 2
  || versions.some((version) => version !== current && version !== current - 1)) {
  throw new Error('Keyring must contain current and optionally the immediately previous version');
}
if (options.action === 'prepare' && (current === 1 ? versions.length !== 1 : !unique.has(current - 1))) {
  throw new Error('Prepare rehearsal requires current plus previous overlap');
}
if (['retire', 'compromised'].includes(options.action) && versions.length !== 1) {
  throw new Error(`${options.action} rehearsal requires the previous or compromised key to be absent`);
}

console.log(JSON.stringify({ kind: options.kind, action: options.action, current, versions, valid: true }));
