import { isIP } from 'node:net';

import type { FastifyRequest } from 'fastify';

function ipv4Prefix(value: string) {
  const octets = value.split('.').map(Number);
  if (octets.length !== 4 || octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
  return `${octets[0]}.${octets[1]}.${octets[2]}.0/24`;
}

function ipv6Hextets(value: string): number[] | null {
  const zone = value.indexOf('%');
  if (zone >= 0) value = value.slice(0, zone);
  const mapped = value.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) {
    const octets = mapped[2]!.split('.').map(Number);
    if (octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
    value = `${mapped[1]}${((octets[0]! << 8) | octets[1]!).toString(16)}:${((octets[2]! << 8) | octets[3]!).toString(16)}`;
  }
  const halves = value.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves[1] ? halves[1].split(':') : [];
  if (halves.length === 1 && left.length !== 8) return null;
  const missing = 8 - left.length - right.length;
  if (missing < (halves.length === 2 ? 1 : 0)) return null;
  const raw = [...left, ...Array(missing).fill('0'), ...right];
  if (raw.length !== 8 || raw.some((part) => !/^[0-9a-f]{1,4}$/i.test(part))) return null;
  return raw.map((part) => Number.parseInt(part, 16));
}

export function normalizeIpPrefix(value: string | undefined): string | null {
  if (!value) return null;
  const withoutZone = value.includes('%') ? value.slice(0, value.indexOf('%')) : value;
  if (isIP(withoutZone) === 4) return ipv4Prefix(withoutZone);
  if (isIP(withoutZone) !== 6) return null;
  const mapped = withoutZone.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (mapped) return ipv4Prefix(mapped[1]!);
  const hextets = ipv6Hextets(withoutZone);
  if (!hextets) return null;
  if (hextets.slice(0, 5).every((part) => part === 0) && hextets[5] === 0xffff) {
    return ipv4Prefix([
      hextets[6]! >> 8,
      hextets[6]! & 0xff,
      hextets[7]! >> 8,
      hextets[7]! & 0xff
    ].join('.'));
  }
  return `${hextets.slice(0, 4).map((part) => part.toString(16)).join(':')}::/64`;
}

export function requestIpPrefix(request: FastifyRequest) {
  const ips = request.ips ?? [];
  const forwarded = request.headers['x-forwarded-for'];
  if (ips.length > 1 && (
    ips.some((address) => normalizeIpPrefix(address) === null)
    || typeof forwarded !== 'string'
    || forwarded.split(',').some((address) => normalizeIpPrefix(address.trim()) === null)
  )) return 'unknown';
  return normalizeIpPrefix(request.ip) ?? 'unknown';
}

export function trustedProxyFromEnvironment(value: string | undefined): false | string {
  if (value === undefined || value === '') return false;
  if (value.trim() !== value) throw new Error('TRUST_PROXY must be a comma-separated IP/CIDR allowlist');
  const entries = value.split(',');
  if (entries.length === 0 || entries.some((entry) => {
    if (!entry || entry.trim() !== entry) return true;
    const [address, rawPrefix, extra] = entry.split('/');
    const family = isIP(address!);
    if (!family || extra !== undefined) return true;
    if (rawPrefix === undefined) return false;
    if (!/^\d+$/.test(rawPrefix)) return true;
    const prefix = Number(rawPrefix);
    return prefix === 0 || prefix > (family === 4 ? 32 : 128);
  })) throw new Error('TRUST_PROXY must be a comma-separated IP/CIDR allowlist');
  return entries.join(',');
}
