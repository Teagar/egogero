export function isValidTimeZone(value: string) {
  if (!/^[A-Za-z_+-]+(?:\/[A-Za-z0-9_+-]+)*$/.test(value)) return false;
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: value }).format();
    return true;
  } catch (error) {
    if (error instanceof RangeError) return false;
    throw error;
  }
}

export function isDatabaseTimeZoneRejection(error: unknown) {
  const seen = new Set<unknown>();
  let current: unknown = error;
  while (current && !seen.has(current)) {
    seen.add(current);
    if (current instanceof Error && current.message.includes('invalid condominium timezone')) return true;
    if (typeof current !== 'object') return false;
    const record = current as Record<string, unknown>;
    if (JSON.stringify(record.meta ?? '').includes('invalid condominium timezone')) return true;
    current = record.cause;
  }
  return false;
}
