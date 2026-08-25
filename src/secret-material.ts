const PLACEHOLDER_PATTERN = /(change[-_ ]?me|replace[-_ ]?me|placeholder|not[-_ ]?a[-_ ]?key|dummy[-_ ]?key|(?:test|example|development)[-_ ]?(?:key|secret))/i;

export function validateDecodedEncryptionKey(key: Buffer, name: string) {
  const frequencies = new Map<number, number>();
  for (const byte of key) frequencies.set(byte, (frequencies.get(byte) ?? 0) + 1);
  const printable = key.every((byte) => byte >= 0x20 && byte <= 0x7e) ? key.toString('ascii') : '';
  if (frequencies.size < 12 || Math.max(...frequencies.values()) > Math.floor(key.length / 4)
    || PLACEHOLDER_PATTERN.test(printable)) {
    throw new Error(`${name} contains degenerate or placeholder key material`);
  }
}

export function assertDistinctSecretMaterial(domains: readonly Buffer[]) {
  for (let left = 0; left < domains.length; left += 1) {
    for (let right = left + 1; right < domains.length; right += 1) {
      if (domains[left]!.equals(domains[right]!)) {
        throw new Error('Secret and encryption key material must not be reused across domains');
      }
    }
  }
}
