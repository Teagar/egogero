import { mkdir, rm } from 'node:fs/promises';
import path from 'node:path';

export default async function setupVisualEvidence() {
  const root = path.resolve('.visual-evidence');
  await rm(root, { recursive: true, force: true });
  await mkdir(path.join(root, 'screenshots'), { recursive: true, mode: 0o700 });
}
