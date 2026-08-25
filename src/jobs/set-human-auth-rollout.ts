import { isUuid } from '../auth.js';
import {
  createHumanAuthRolloutService,
  HUMAN_AUTH_COHORT_PERCENTAGES,
  HUMAN_AUTH_ROLLOUT_STATES,
  type HumanAuthRolloutState
} from '../human-auth-rollout.js';
import { prisma } from '../lib/prisma.js';

function parseArguments(values: string[]) {
  const options = new Map<string, string>();
  for (let index = 0; index < values.length; index += 2) {
    const name = values[index];
    const value = values[index + 1];
    if (!name?.startsWith('--') || value === undefined || options.has(name)) throw new Error('invalid arguments');
    options.set(name, value);
  }
  if ([...options.keys()].some((key) => !['--actor', '--scope', '--state', '--cohort'].includes(key))) {
    throw new Error('invalid arguments');
  }
  const actorAccountId = options.get('--actor');
  const scope = options.get('--scope');
  const state = options.get('--state');
  const rawCohort = options.get('--cohort');
  const authorizationToken = process.env.HUMAN_AUTH_ROLLOUT_AUTHORIZATION_TOKEN;
  const tenantId = scope?.startsWith('tenant:') ? scope.slice('tenant:'.length) : null;
  const cohortPercentage = rawCohort === undefined ? null : Number(rawCohort);
  if (!isUuid(actorAccountId) || (scope !== 'global' && !isUuid(tenantId))
    || !authorizationToken || authorizationToken.length < 32 || authorizationToken.length > 1024
    || !state || !HUMAN_AUTH_ROLLOUT_STATES.includes(state as HumanAuthRolloutState)
    || (tenantId !== null && state === 'internal-provider')
    || (state === 'pilot'
      ? !HUMAN_AUTH_COHORT_PERCENTAGES.includes(cohortPercentage as 10 | 50 | 100)
      : cohortPercentage !== null)) {
    throw new Error('invalid arguments');
  }
  return { actorAccountId, condominioId: tenantId, state: state as HumanAuthRolloutState, cohortPercentage,
    authorization: { kind: 'deployment' as const, token: authorizationToken } };
}

try {
  const input = parseArguments(process.argv.slice(2));
  const result = await createHumanAuthRolloutService(prisma).setPolicy({
    ...input,
    requestCorrelationId: `cli-${process.pid}`
  });
  if (!result) throw new Error('provider or scope not found');
  process.stdout.write(`${JSON.stringify(result)}\n`);
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : 'rollout command failed'}\n`);
  process.exitCode = 1;
} finally {
  await prisma.$disconnect();
}
