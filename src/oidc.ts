import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  randomUUID,
  timingSafeEqual
} from 'node:crypto';

import { Prisma } from '@prisma/client';
import type { PrismaClient } from '@prisma/client';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import {
  createRemoteJWKSet,
  customFetch as joseCustomFetch,
  jwtVerify
} from 'jose';
import * as oidc from 'openid-client';

import { hasBrowserSessionCookie, parseBrowserSessionCookie } from './sessions.js';
import type { BrowserSessionService, BrowserSessionStore } from './sessions.js';
import { digestSecret, exactOidcIssuer, normalizeProvisioningEmail } from './human-administration.js';
import type { HumanAdministrationService } from './human-administration.js';
import type { AuthRateLimiter } from './auth-rate-limits.js';
import { noopAuthAlerts, noopAuthMetrics, safeAuthAlerts, safeAuthMetrics } from './auth-observability.js';
import type { AuthAlertSink, AuthMetrics } from './auth-observability.js';
import { requestIpPrefix } from './client-ip.js';
import type { HumanAuthRolloutGate } from './human-auth-rollout.js';
import { validateDecodedEncryptionKey } from './secret-material.js';

const LOGIN_TRANSACTION_TTL_MS = 10 * 60 * 1000;
const OIDC_CLOCK_TOLERANCE_SECONDS = 60;
const OIDC_HTTP_TIMEOUT_SECONDS = 5;
const MAX_OIDC_RESPONSE_BYTES = 1024 * 1024;
const HANDOFF_TTL_MS = 5 * 60 * 1000;
export const HANDOFF_COOKIE = '__Host-eg_oidc_handoff';
export const CLEARED_HANDOFF_COOKIE = `${HANDOFF_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
const DEFAULT_FAILURE_PATH = '/auth/error';
const SAFE_ID_TOKEN_ALGORITHMS = new Set(['RS256', 'PS256', 'ES256', 'EdDSA']);

export type OidcRuntimeConfig = {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  idTokenSigningAlgorithm: string;
  failurePath: string;
  returnToPrefixes: readonly string[];
  currentPkceKeyVersion: number;
  pkceKeys: ReadonlyMap<number, Buffer>;
};

type AuditInput = {
  eventType: string;
  outcome: 'success' | 'failure' | 'denied';
  requestCorrelationId: string;
  reasonCode?: string;
  accountId?: string;
  externalIdentityId?: string;
  metadata?: Record<string, boolean | number | string>;
};

type LoginTransactionInput = {
  id: string;
  expiresAt: Date;
  stateDigest: Buffer;
  nonceDigest: Buffer;
  pkceVerifierCiphertext: Buffer;
  pkceVerifierNonce: Buffer;
  pkceVerifierAuthTag: Buffer;
  pkceKeyVersion: number;
  issuer: string;
  clientId: string;
  redirectUri: string;
  returnTo: string;
  recoveryIntent: boolean;
  invitationTokenDigest?: Buffer;
  reauthenticationIntent?: boolean;
  reauthenticationFamilyId?: string;
  audit: AuditInput;
};

type ConsumedLoginTransaction = Omit<LoginTransactionInput, 'expiresAt' | 'audit'> & {
  createdAt: Date;
  returnTo: string;
  recoveryIntent: boolean;
};

export type ValidatedOidcIdentity = {
  accountId: string;
  externalIdentityId: string;
  issuer: string;
  subject: string;
  authenticatedAt: Date;
  authenticationMethods?: string[];
  assuranceContext?: string | null;
  recoveryIntent?: boolean;
};

export interface OidcLoginStore {
  createTransaction(input: LoginTransactionInput): Promise<void>;
  consumeTransaction(stateDigest: Buffer): Promise<ConsumedLoginTransaction | null>;
  completeIdentity(input: {
    loginTransactionId: string;
    issuer: string;
    subject: string;
    email: string | null;
    emailVerified: boolean;
    authenticatedAt: Date;
    authenticationMethods?: string[];
    assuranceContext?: string | null;
    invitationTokenDigest?: Buffer;
    recoveryIntent?: boolean;
    reauthenticationIntent?: boolean;
    reauthenticationFamilyId?: string;
    handoffId: string;
    handoffDigest: Buffer;
    handoffExpiresAt: Date;
    audit: AuditInput;
  }): Promise<ValidatedOidcIdentity | null>;
  consumeHandoff(handleDigest: Buffer): Promise<ValidatedOidcIdentity | null>;
  appendAudit(input: AuditInput): Promise<void>;
}

export interface OidcService {
  readonly failurePath: string;
  startLogin(input: {
    returnTo?: string;
    requestCorrelationId: string;
    reauthentication?: boolean;
    reauthenticationFamilyId?: string;
    invitationToken?: string;
    recovery?: boolean;
  }): Promise<URL>;
  completeCallback(input: {
    callbackUrl: URL;
    requestCorrelationId: string;
    ipPrefix?: string;
  }): Promise<{ returnTo: string; identity: ValidatedOidcIdentity; handoffToken: string }>;
}

export class OidcCallbackError extends Error {
  constructor() {
    super('OIDC callback failed');
    this.name = 'OidcCallbackError';
  }
}

export class AuthRateLimitError extends Error {
  constructor(readonly retryAfterSeconds: number) {
    super('Authentication rate limit exceeded');
    this.name = 'AuthRateLimitError';
  }
}

class AuditedOidcCallbackError extends OidcCallbackError {}

function requireEnvironment(environment: NodeJS.ProcessEnv, name: string) {
  const value = environment[name];
  if (!value || value.trim() !== value) throw new Error(`${name} is required`);
  return value;
}

function parseExactHttpsUrl(value: string, name: string) {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${name} must be an exact HTTPS URL`);
  }
  if (
    parsed.protocol !== 'https:'
    || parsed.username
    || parsed.password
    || parsed.search
    || parsed.hash
    || !parsed.hostname
  ) {
    throw new Error(`${name} must be an exact HTTPS URL`);
  }
  return value;
}

function hasControlCharacters(value: string) {
  return Array.from(value).some((character) => {
    const code = character.charCodeAt(0);
    return code <= 31 || code === 127;
  });
}

function normalizeSafeRelativePath(value: string | undefined, fallback: string, prefixes: readonly string[]) {
  if (!value || value.length > 2048 || !value.startsWith('/') || value.startsWith('//')) return fallback;
  if (value.includes('\\') || value.includes('#') || hasControlCharacters(value)) return fallback;

  let decoded: string;
  try {
    decoded = decodeURIComponent(value);
  } catch {
    return fallback;
  }
  if (decoded.startsWith('//') || decoded.includes('\\') || hasControlCharacters(decoded)) return fallback;

  const parsed = new URL(value, 'https://egogero.invalid');
  if (parsed.origin !== 'https://egogero.invalid' || parsed.hash) return fallback;
  const normalized = `${parsed.pathname}${parsed.search}`;
  const allowed = prefixes.some((prefix) =>
    prefix === '/' || normalized === prefix || normalized.startsWith(`${prefix}/`) || normalized.startsWith(`${prefix}?`)
  );
  return allowed ? normalized : fallback;
}

function parsePkceKeys(environment: NodeJS.ProcessEnv) {
  const serialized = requireEnvironment(environment, 'OIDC_PKCE_KEYS');
  let parsed: unknown;
  try {
    parsed = JSON.parse(serialized);
  } catch {
    throw new Error('OIDC_PKCE_KEYS must be a JSON object of versioned base64url keys');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('OIDC_PKCE_KEYS must be a JSON object of versioned base64url keys');
  }

  const keys = new Map<number, Buffer>();
  for (const [rawVersion, rawKey] of Object.entries(parsed)) {
    const version = Number(rawVersion);
    if (!Number.isSafeInteger(version) || version <= 0 || rawVersion !== String(version)
      || typeof rawKey !== 'string' || !/^[A-Za-z0-9_-]+$/.test(rawKey)) {
      throw new Error('OIDC_PKCE_KEYS contains an invalid version or key');
    }
    const key = Buffer.from(rawKey, 'base64url');
    if (key.length !== 32 || key.toString('base64url') !== rawKey || keys.has(version)) {
      throw new Error('OIDC_PKCE_KEYS contains an invalid version or key');
    }
    validateDecodedEncryptionKey(key, 'OIDC_PKCE_KEYS');
    if ([...keys.values()].some((existing) => existing.equals(key))) {
      throw new Error('OIDC_PKCE_KEYS must not reuse key bytes across versions');
    }
    keys.set(version, key);
  }
  if (keys.size === 0) throw new Error('OIDC_PKCE_KEYS must contain at least one active key');
  return keys;
}

function validateKeyOverlap(keys: ReadonlyMap<number, Buffer>, currentVersion: number, name: string) {
  const expected = new Set([currentVersion, ...(currentVersion > 1 ? [currentVersion - 1] : [])]);
  if (keys.size > 2 || [...keys.keys()].some((version) => !expected.has(version))) {
    throw new Error(`${name} may contain only the current and immediately previous key versions`);
  }
}

function hasAdequateSecretStrength(value: string) {
  return Buffer.byteLength(value) >= 32 && new Set(value).size >= 12
    && !/(change[-_ ]?me|placeholder|example|secret){2,}/i.test(value);
}

export function oidcConfigFromEnvironment(environment: NodeJS.ProcessEnv): OidcRuntimeConfig | undefined {
  if (environment.HUMAN_AUTH_ENABLED === undefined || environment.HUMAN_AUTH_ENABLED === 'false') return undefined;
  if (environment.HUMAN_AUTH_ENABLED !== 'true') {
    throw new Error('HUMAN_AUTH_ENABLED must be true or false');
  }

  const issuer = exactOidcIssuer(requireEnvironment(environment, 'OIDC_ISSUER'), 'OIDC_ISSUER');
  const authorizationEndpoint = parseExactHttpsUrl(
    requireEnvironment(environment, 'OIDC_AUTHORIZATION_ENDPOINT'),
    'OIDC_AUTHORIZATION_ENDPOINT'
  );
  const tokenEndpoint = parseExactHttpsUrl(
    requireEnvironment(environment, 'OIDC_TOKEN_ENDPOINT'),
    'OIDC_TOKEN_ENDPOINT'
  );
  const jwksUri = parseExactHttpsUrl(requireEnvironment(environment, 'OIDC_JWKS_URI'), 'OIDC_JWKS_URI');
  const redirectUri = parseExactHttpsUrl(
    requireEnvironment(environment, 'OIDC_REDIRECT_URI'),
    'OIDC_REDIRECT_URI'
  );
  if (new URL(redirectUri).pathname !== '/auth/callback') {
    throw new Error('OIDC_REDIRECT_URI must use the /auth/callback path');
  }

  const clientId = requireEnvironment(environment, 'OIDC_CLIENT_ID');
  if (clientId.length > 255) throw new Error('OIDC_CLIENT_ID is invalid');
  const clientSecret = requireEnvironment(environment, 'OIDC_CLIENT_SECRET');
  if (!hasAdequateSecretStrength(clientSecret)) {
    throw new Error('OIDC_CLIENT_SECRET must be at least 32 bytes and have adequate entropy');
  }

  const idTokenSigningAlgorithm = requireEnvironment(environment, 'OIDC_ID_TOKEN_SIGNING_ALG');
  if (!SAFE_ID_TOKEN_ALGORITHMS.has(idTokenSigningAlgorithm)) {
    throw new Error('OIDC_ID_TOKEN_SIGNING_ALG is not allowed');
  }

  const pkceKeys = parsePkceKeys(environment);
  const currentPkceKeyVersion = Number(requireEnvironment(environment, 'OIDC_PKCE_CURRENT_KEY_VERSION'));
  if (!Number.isSafeInteger(currentPkceKeyVersion) || !pkceKeys.has(currentPkceKeyVersion)) {
    throw new Error('OIDC_PKCE_CURRENT_KEY_VERSION must identify an active key');
  }
  validateKeyOverlap(pkceKeys, currentPkceKeyVersion, 'OIDC_PKCE_KEYS');

  const rawPrefixes = environment.OIDC_RETURN_TO_PREFIXES?.split(',').map((value) => value.trim()) ?? ['/'];
  if (
    rawPrefixes.length === 0
    || rawPrefixes.some((value) => normalizeSafeRelativePath(value, '', ['/']) !== value || value.includes('?'))
  ) {
    throw new Error('OIDC_RETURN_TO_PREFIXES must contain safe comma-separated paths');
  }
  const failurePath = normalizeSafeRelativePath(environment.OIDC_FAILURE_PATH, DEFAULT_FAILURE_PATH, ['/']);
  if (environment.OIDC_FAILURE_PATH && failurePath !== environment.OIDC_FAILURE_PATH) {
    throw new Error('OIDC_FAILURE_PATH must be a safe relative path');
  }

  return {
    issuer,
    authorizationEndpoint,
    tokenEndpoint,
    jwksUri,
    clientId,
    clientSecret,
    redirectUri,
    idTokenSigningAlgorithm,
    failurePath,
    returnToPrefixes: rawPrefixes,
    currentPkceKeyVersion,
    pkceKeys
  };
}

function digest(value: string) {
  return createHash('sha256').update(value, 'utf8').digest();
}

function pkceAad(config: Pick<OidcRuntimeConfig, 'issuer' | 'clientId' | 'redirectUri'>, id: string, version: number) {
  return Buffer.from(JSON.stringify(['egogero-pkce-v1', id, config.issuer, config.clientId, config.redirectUri, version]));
}

function encryptPkceVerifier(config: OidcRuntimeConfig, id: string, verifier: string) {
  const key = config.pkceKeys.get(config.currentPkceKeyVersion);
  if (!key) throw new Error('OIDC PKCE encryption key unavailable');
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(pkceAad(config, id, config.currentPkceKeyVersion));
  return {
    ciphertext: Buffer.concat([cipher.update(verifier, 'utf8'), cipher.final()]),
    nonce,
    authTag: cipher.getAuthTag()
  };
}

function decryptPkceVerifier(config: OidcRuntimeConfig, transaction: ConsumedLoginTransaction) {
  const key = config.pkceKeys.get(transaction.pkceKeyVersion);
  if (!key) throw new OidcCallbackError();
  let plaintext: Buffer | undefined;
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, transaction.pkceVerifierNonce);
    decipher.setAAD(pkceAad(transaction, transaction.id, transaction.pkceKeyVersion));
    decipher.setAuthTag(transaction.pkceVerifierAuthTag);
    plaintext = Buffer.concat([
      decipher.update(transaction.pkceVerifierCiphertext),
      decipher.final()
    ]);
    const verifier = plaintext.toString('utf8');
    if (!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) throw new OidcCallbackError();
    return verifier;
  } catch {
    throw new OidcCallbackError();
  } finally {
    plaintext?.fill(0);
  }
}

function boundedCorrelationId(value: string) {
  return value.length > 128 ? createHash('sha256').update(value).digest('hex') : value;
}

function auditValues(input: AuditInput) {
  return {
    id: randomUUID(),
    eventType: input.eventType,
    outcome: input.outcome,
    accountId: input.accountId ?? null,
    externalIdentityId: input.externalIdentityId ?? null,
    actorType: input.accountId ? 'human' : 'anonymous',
    actorId: input.accountId ?? null,
    requestCorrelationId: boundedCorrelationId(input.requestCorrelationId),
    reasonCode: input.reasonCode ?? null,
    metadata: JSON.stringify(input.metadata ?? {})
  };
}

async function insertAudit(transaction: Prisma.TransactionClient, input: AuditInput) {
  const values = auditValues(input);
  await transaction.$executeRaw`
    INSERT INTO "AuthenticationAuditEvent" (
      id, "eventType", outcome, "accountId", "externalIdentityId", "actorType", "actorId",
      "requestCorrelationId", "reasonCode", metadata
    ) VALUES (
      ${values.id}::uuid, ${values.eventType}, ${values.outcome}::"AuthenticationOutcome",
      ${values.accountId}::uuid, ${values.externalIdentityId}::uuid,
      ${values.actorType}::"AuthenticationActorType", ${values.actorId},
      ${values.requestCorrelationId}, ${values.reasonCode}, ${values.metadata}::jsonb
    )
  `;
}

export function createPrismaOidcLoginStore(client: PrismaClient, rolloutGate: HumanAuthRolloutGate): OidcLoginStore {
  if (!rolloutGate) throw new Error('OidcLoginStore requires a HumanAuthRolloutGate');
  return {
    async createTransaction(input) {
      await client.$transaction(async (transaction) => {
        await transaction.$executeRaw`
          INSERT INTO "OidcLoginTransaction" (
            id, "expiresAt", "stateDigest", "nonceDigest", "pkceVerifierCiphertext",
            "pkceVerifierNonce", "pkceVerifierAuthTag", "pkceKeyVersion", issuer,
             "clientId", "redirectUri", "returnTo", "recoveryIntent", "reauthenticationIntent",
             "reauthenticationFamilyId", "invitationTokenDigest"
          ) VALUES (
            ${input.id}::uuid, ${input.expiresAt}, ${input.stateDigest}, ${input.nonceDigest},
            ${input.pkceVerifierCiphertext}, ${input.pkceVerifierNonce}, ${input.pkceVerifierAuthTag},
            ${input.pkceKeyVersion}, ${input.issuer}, ${input.clientId}, ${input.redirectUri},
             ${input.returnTo}, ${input.recoveryIntent}, ${input.reauthenticationIntent === true},
              ${input.reauthenticationFamilyId ?? null}::uuid, ${input.invitationTokenDigest ?? null}
          )
        `;
        await insertAudit(transaction, input.audit);
      });
    },

    async consumeTransaction(stateDigest) {
      const rows = await client.$queryRaw<ConsumedLoginTransaction[]>(Prisma.sql`
        UPDATE "OidcLoginTransaction"
        SET "consumedAt" = clock_timestamp()
        WHERE "stateDigest" = ${stateDigest}
          AND "consumedAt" IS NULL
          AND "expiresAt" > clock_timestamp()
        RETURNING id, "createdAt", "stateDigest", "nonceDigest", "pkceVerifierCiphertext",
                  "pkceVerifierNonce", "pkceVerifierAuthTag", "pkceKeyVersion",
                   issuer, "clientId", "redirectUri", "returnTo", "reauthenticationIntent",
                    "reauthenticationFamilyId", "recoveryIntent", "invitationTokenDigest"
      `);
      return rows[0] ?? null;
    },

    async completeIdentity(input) {
      return client.$transaction(async (transaction) => {
        const normalizedEmail = typeof input.email === 'string' ? normalizeProvisioningEmail(input.email) : null;
        if (input.invitationTokenDigest) {
          if (!input.emailVerified || !normalizedEmail) {
            await insertAudit(transaction, { ...input.audit, eventType: 'account_invitation_accept_failed',
              outcome: 'denied', reasonCode: 'invitation_validation_failed' });
            return null;
          }
          const invitations = await transaction.$queryRaw<Array<{ id: string; accountId: string; membershipId: string }>>(Prisma.sql`
            SELECT invitation.id, invitation."accountId", invitation."membershipId"
            FROM "HumanProvisioningInvitation" invitation
            JOIN "HumanAccount" account ON account.id = invitation."accountId"
            JOIN "HumanMembership" membership ON membership.id = invitation."membershipId"
              AND membership."accountId" = account.id
            WHERE invitation."tokenDigest" = ${input.invitationTokenDigest}
              AND invitation."consumedAt" IS NULL AND invitation."disabledAt" IS NULL
              AND invitation."expiresAt" > clock_timestamp()
              AND invitation."expectedEmail" = ${normalizedEmail}
              AND account.status = 'invited' AND membership.status = 'invited'
            FOR UPDATE OF invitation, account, membership
          `);
          const invitation = invitations[0];
          if (!invitation) {
            await insertAudit(transaction, { ...input.audit, eventType: 'account_invitation_accept_failed',
              outcome: 'denied', reasonCode: 'invitation_validation_failed' });
            return null;
          }
          const invitationMembership = await transaction.$queryRaw<Array<{ condominioId: string | null; role: string }>>`
            SELECT "condominioId", role::text FROM "HumanMembership" WHERE id = ${invitation.membershipId}::uuid
          `;
          const invitationGate = invitationMembership[0]
            ? await rolloutGate.gateScope(transaction, invitationMembership[0].condominioId,
                invitationMembership[0].role === 'provedor')
            : { allowed: false, reason: 'rollout_unavailable' };
          if (!invitationGate.allowed) {
            await insertAudit(transaction, { ...input.audit, eventType: 'account_invitation_accept_failed',
              outcome: 'denied', reasonCode: 'rollout_disabled' });
            return null;
          }
          const identityId = randomUUID();
          const inserted = await transaction.$executeRaw`
            INSERT INTO "ExternalIdentity" (id, "accountId", issuer, subject, email, "emailVerified", "lastLoginAt")
            VALUES (${identityId}::uuid, ${invitation.accountId}::uuid, ${input.issuer}, ${input.subject},
              ${normalizedEmail}, true, clock_timestamp()) ON CONFLICT (issuer, subject) DO NOTHING
          `;
          if (inserted !== 1) {
            await insertAudit(transaction, { ...input.audit, eventType: 'account_invitation_accept_failed',
              outcome: 'denied', reasonCode: 'identity_already_bound' });
            return null;
          }
          await transaction.$executeRaw`
            UPDATE "HumanProvisioningInvitation" SET "consumedAt" = clock_timestamp()
            WHERE id = ${invitation.id}::uuid AND "consumedAt" IS NULL
          `;
          await transaction.$executeRaw`UPDATE "HumanAccount" SET status = 'active', "updatedAt" = clock_timestamp() WHERE id = ${invitation.accountId}::uuid`;
          await transaction.$executeRaw`UPDATE "HumanMembership" SET status = 'active' WHERE id = ${invitation.membershipId}::uuid`;
          await transaction.$executeRaw`
            INSERT INTO "OidcValidatedHandoff" (
              id, "expiresAt", "handleDigest", "loginTransactionId", "accountId", "externalIdentityId",
              "authenticatedAt", "authenticationMethods", "assuranceContext", "recoveryIntent"
            ) VALUES (${input.handoffId}::uuid, ${input.handoffExpiresAt}, ${input.handoffDigest},
              ${input.loginTransactionId}::uuid, ${invitation.accountId}::uuid, ${identityId}::uuid,
              ${input.authenticatedAt}, ${input.authenticationMethods ?? []}, ${input.assuranceContext ?? null}, false)
          `;
          await insertAudit(transaction, { ...input.audit, eventType: 'account_invitation_accepted', outcome: 'success',
            accountId: invitation.accountId, externalIdentityId: identityId });
          return { accountId: invitation.accountId, externalIdentityId: identityId, issuer: input.issuer,
            subject: input.subject, authenticatedAt: input.authenticatedAt,
            authenticationMethods: input.authenticationMethods ?? [], assuranceContext: input.assuranceContext ?? null,
            recoveryIntent: false };
        }

        const identities = await transaction.$queryRaw<Array<{
          id: string;
          accountId: string;
        }>>(Prisma.sql`
          SELECT identity.id, identity."accountId"
          FROM "ExternalIdentity" identity
          JOIN "HumanAccount" account ON account.id = identity."accountId"
          WHERE identity.issuer = ${input.issuer}
            AND identity.subject = ${input.subject}
            AND account.status = 'active'
          FOR UPDATE OF identity, account
        `);
        const identity = identities[0];
        if (!identity) {
          await insertAudit(transaction, {
            ...input.audit,
            eventType: 'oidc_callback_failed',
            outcome: 'denied',
            reasonCode: 'access_not_provisioned'
          });
          return null;
        }
        const decision = await rolloutGate.gateIdentity(transaction, identity.accountId);
        if (!decision.allowed) {
          await insertAudit(transaction, { ...input.audit, eventType: 'oidc_callback_failed',
            outcome: 'denied', reasonCode: 'rollout_disabled' });
          return null;
        }

        await transaction.$executeRaw`
          UPDATE "ExternalIdentity"
          SET email = ${input.email}, "emailVerified" = ${input.emailVerified},
              "lastLoginAt" = clock_timestamp()
          WHERE id = ${identity.id}::uuid
        `;
        await transaction.$executeRaw`
          INSERT INTO "OidcValidatedHandoff" (
            id, "expiresAt", "handleDigest", "loginTransactionId", "accountId",
              "externalIdentityId", "authenticatedAt", "authenticationMethods", "assuranceContext", "recoveryIntent",
              "reauthenticationIntent", "reauthenticationFamilyId"
          ) VALUES (
            ${input.handoffId}::uuid, ${input.handoffExpiresAt}, ${input.handoffDigest},
            ${input.loginTransactionId}::uuid, ${identity.accountId}::uuid,
              ${identity.id}::uuid, ${input.authenticatedAt}, ${input.authenticationMethods ?? []},
              ${input.assuranceContext ?? null}, ${input.recoveryIntent === true}, ${input.reauthenticationIntent === true},
             ${input.reauthenticationFamilyId ?? null}::uuid
          )
        `;
        await insertAudit(transaction, {
          ...input.audit,
          accountId: identity.accountId,
          externalIdentityId: identity.id
        });
        return {
          accountId: identity.accountId,
          externalIdentityId: identity.id,
          issuer: input.issuer,
          subject: input.subject,
          authenticatedAt: input.authenticatedAt,
          authenticationMethods: input.authenticationMethods ?? [],
          assuranceContext: input.assuranceContext ?? null,
          recoveryIntent: input.recoveryIntent === true
        };
      });
    },

    async consumeHandoff(handleDigest) {
      const rows = await client.$queryRaw<ValidatedOidcIdentity[]>(Prisma.sql`
        UPDATE "OidcValidatedHandoff" handoff
        SET "consumedAt" = clock_timestamp()
        FROM "ExternalIdentity" identity, "HumanAccount" account
        WHERE handoff."handleDigest" = ${handleDigest}
          AND handoff."consumedAt" IS NULL
          AND handoff."expiresAt" > clock_timestamp()
          AND identity.id = handoff."externalIdentityId"
          AND identity."accountId" = handoff."accountId"
          AND account.id = handoff."accountId"
          AND account.status = 'active'
        RETURNING handoff."accountId", handoff."externalIdentityId",
                  identity.issuer, identity.subject, handoff."authenticatedAt",
                  handoff."authenticationMethods", handoff."assuranceContext", handoff."recoveryIntent"
      `);
      return rows[0] ?? null;
    },

    async appendAudit(input) {
      await client.$transaction((transaction) => insertAudit(transaction, input));
    }
  };
}

function discoveryUrl(issuer: string) {
  return `${issuer.replace(/\/$/, '')}/.well-known/openid-configuration`;
}

function createExactOidcFetch(
  config: OidcRuntimeConfig,
  implementation: typeof fetch
): oidc.CustomFetch {
  const allowed = new Map([
    [discoveryUrl(config.issuer), 'GET'],
    [config.jwksUri, 'GET'],
    [config.tokenEndpoint, 'POST']
  ]);

  return async (url, options) => {
    const expectedMethod = allowed.get(url);
    if (!expectedMethod || options.method.toUpperCase() !== expectedMethod) {
      throw new Error('OIDC endpoint is not allowlisted');
    }
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.hash) {
      throw new Error('OIDC endpoint is not allowlisted');
    }

    const response = await implementation(url, {
      ...options,
      redirect: 'error'
    } as RequestInit);
    if (response.status >= 300 && response.status < 400) {
      throw new Error('OIDC endpoint redirects are forbidden');
    }
    const contentLength = Number(response.headers.get('content-length'));
    if (Number.isFinite(contentLength) && contentLength > MAX_OIDC_RESPONSE_BYTES) {
      await response.body?.cancel();
      throw new Error('OIDC response is too large');
    }
    const chunks: Uint8Array[] = [];
    let total = 0;
    if (response.body) {
      const reader = response.body.getReader();
      while (true) {
        const next = await reader.read();
        if (next.done) break;
        total += next.value.byteLength;
        if (total > MAX_OIDC_RESPONSE_BYTES) {
          await reader.cancel();
          throw new Error('OIDC response is too large');
        }
        chunks.push(next.value);
      }
    }
    const body = Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)), total);
    return new Response(body, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers
    });
  };
}

function validateJwksDocument(config: OidcRuntimeConfig, document: unknown) {
  const keys = document && typeof document === 'object' && 'keys' in document
    ? (document as { keys?: unknown }).keys
    : undefined;
  if (!Array.isArray(keys) || !keys.some((key) => {
    if (!key || typeof key !== 'object') return false;
    const candidate = key as Record<string, unknown>;
    const algorithmMatches = (
      (['RS256', 'PS256'].includes(config.idTokenSigningAlgorithm)
        && candidate.kty === 'RSA' && typeof candidate.n === 'string' && typeof candidate.e === 'string')
      || (config.idTokenSigningAlgorithm === 'ES256'
        && candidate.kty === 'EC' && candidate.crv === 'P-256'
        && typeof candidate.x === 'string' && typeof candidate.y === 'string')
      || (config.idTokenSigningAlgorithm === 'EdDSA'
        && candidate.kty === 'OKP' && candidate.crv === 'Ed25519' && typeof candidate.x === 'string')
    );
    return algorithmMatches && candidate.use !== 'enc'
      && (candidate.alg === undefined || candidate.alg === config.idTokenSigningAlgorithm)
      && typeof candidate.kid === 'string'
      && ['RSA', 'EC', 'OKP'].includes(String(candidate.kty));
  })) {
    throw new Error('OIDC JWKS has no usable signing key');
  }
}

async function exchangeAuthorizationCode(
  config: OidcRuntimeConfig,
  exactFetch: oidc.CustomFetch,
  keySet: ReturnType<typeof createRemoteJWKSet>,
  code: string,
  verifier: string
) {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: config.redirectUri,
    client_id: config.clientId,
    code_verifier: verifier
  });
  const formEncode = (value: string) => new URLSearchParams({ value }).toString().slice('value='.length);
  const encodedCredentials = `${formEncode(config.clientId)}:${formEncode(config.clientSecret)}`;
  const response = await exactFetch(config.tokenEndpoint, {
    method: 'POST',
    headers: {
      accept: 'application/json',
      authorization: `Basic ${Buffer.from(encodedCredentials).toString('base64')}`,
      'content-type': 'application/x-www-form-urlencoded'
    },
    redirect: 'manual',
    body,
    signal: AbortSignal.timeout(OIDC_HTTP_TIMEOUT_SECONDS * 1000)
  });
  if (response.status !== 200 || !response.headers.get('content-type')?.toLowerCase().includes('application/json')) {
    throw new OidcCallbackError();
  }
  let document: unknown;
  try {
    document = await response.json();
  } catch {
    throw new OidcCallbackError();
  }
  if (!document || typeof document !== 'object') {
    throw new OidcCallbackError();
  }
  const tokenResponse = document as Record<string, unknown>;
  if (
    tokenResponse.error !== undefined
    || typeof tokenResponse.access_token !== 'string'
    || tokenResponse.access_token.length === 0
    || typeof tokenResponse.token_type !== 'string'
    || tokenResponse.token_type.toLowerCase() !== 'bearer'
    || typeof tokenResponse.id_token !== 'string'
    || tokenResponse.id_token.length === 0
  ) {
    throw new OidcCallbackError();
  }
  const verify = () => jwtVerify(tokenResponse.id_token as string, keySet, {
    algorithms: [config.idTokenSigningAlgorithm],
    issuer: config.issuer,
    audience: config.clientId,
    clockTolerance: OIDC_CLOCK_TOLERANCE_SECONDS,
    requiredClaims: ['iss', 'aud', 'sub', 'iat', 'exp', 'nonce']
  });
  let verified: Awaited<ReturnType<typeof verify>>;
  try {
    verified = await verify();
  } catch (error) {
    const code = error && typeof error === 'object' && 'code' in error ? String(error.code) : '';
    if (!['ERR_JWKS_NO_MATCHING_KEY', 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED'].includes(code)) throw error;
    await keySet.reload();
    verified = await verify();
  }
  const rawAudience = verified.payload.aud;
  if (
    !(typeof rawAudience === 'string' && rawAudience.length > 0)
    && !(Array.isArray(rawAudience) && rawAudience.length > 0
      && rawAudience.every((audience) => typeof audience === 'string' && audience.length > 0))
  ) {
    throw new OidcCallbackError();
  }
  const audiences = Array.isArray(verified.payload.aud)
    ? verified.payload.aud
    : [verified.payload.aud];
  if ((audiences.length > 1 || verified.payload.azp !== undefined) && verified.payload.azp !== config.clientId) {
    throw new OidcCallbackError();
  }
  return verified.payload;
}

export async function createOidcService(
  config: OidcRuntimeConfig,
  store: OidcLoginStore,
  fetchImplementation: typeof fetch,
  dependencies: { rolloutGate: HumanAuthRolloutGate; rateLimiter?: AuthRateLimiter; metrics?: AuthMetrics;
    alerts?: AuthAlertSink }
): Promise<OidcService> {
  if (!dependencies?.rolloutGate) throw new Error('OidcService requires a HumanAuthRolloutGate');
  const metrics = safeAuthMetrics(dependencies.metrics ?? noopAuthMetrics);
  const alerts = safeAuthAlerts(dependencies.alerts ?? noopAuthAlerts);
  const exactFetch = createExactOidcFetch(config, fetchImplementation);
  let clientConfiguration: oidc.Configuration;
  let keySet: ReturnType<typeof createRemoteJWKSet>;
  let authorizationResponseIssuerRequired = false;
  try {
    clientConfiguration = await oidc.discovery(
      new URL(config.issuer),
      config.clientId,
      {
        client_secret: config.clientSecret,
        redirect_uris: [config.redirectUri],
        response_types: ['code'],
        id_token_signed_response_alg: config.idTokenSigningAlgorithm,
        [oidc.clockTolerance]: OIDC_CLOCK_TOLERANCE_SECONDS
      },
      oidc.ClientSecretBasic(config.clientSecret),
      {
        [oidc.customFetch]: exactFetch,
        timeout: OIDC_HTTP_TIMEOUT_SECONDS
      }
    );
    const metadata = clientConfiguration.serverMetadata();
    if (
      metadata.issuer !== config.issuer
      || metadata.authorization_endpoint !== config.authorizationEndpoint
      || metadata.token_endpoint !== config.tokenEndpoint
      || metadata.jwks_uri !== config.jwksUri
      || !metadata.supportsPKCE('S256')
      || !metadata.response_types_supported?.includes('code')
      || !metadata.id_token_signing_alg_values_supported?.includes(config.idTokenSigningAlgorithm)
      || !metadata.subject_types_supported?.length
      || !metadata.scopes_supported?.includes('openid')
      || (metadata.grant_types_supported !== undefined
        && !metadata.grant_types_supported.includes('authorization_code'))
      || (metadata.response_modes_supported !== undefined
        && !metadata.response_modes_supported.includes('query'))
      || (metadata.token_endpoint_auth_methods_supported !== undefined
        && !metadata.token_endpoint_auth_methods_supported.includes('client_secret_basic'))
    ) {
      throw new Error('OIDC discovery metadata does not match configuration');
    }
    authorizationResponseIssuerRequired = metadata.authorization_response_iss_parameter_supported === true;
    keySet = createRemoteJWKSet(new URL(config.jwksUri), {
      timeoutDuration: OIDC_HTTP_TIMEOUT_SECONDS * 1000,
      cooldownDuration: 30_000,
      cacheMaxAge: 10 * 60 * 1000,
      [joseCustomFetch]: (url, options) => exactFetch(url, {
        method: 'GET',
        headers: Object.fromEntries(options.headers.entries()),
        redirect: 'manual',
        body: undefined,
        signal: options.signal
      })
    });
    await keySet.reload();
    validateJwksDocument(config, keySet.jwks());
  } catch {
    alerts.emit('provider_configuration_drift', { operation: 'oidc_initialization', outcome: 'contract_mismatch' });
    alerts.emit('crypto_key_failure', { operation: 'oidc_initialization' });
    try {
      await store.appendAudit({
        eventType: 'oidc_configuration_failed',
        outcome: 'failure',
        requestCorrelationId: 'startup',
        reasonCode: 'oidc_configuration_failed'
      });
    } catch {
      console.error('OIDC audit persistence unavailable');
    }
    throw new Error('OIDC initialization failed');
  }

  async function appendFailureAudit(
    reasonCode: string,
    requestCorrelationId: string,
    reservationId?: string
  ) {
    try {
      await store.appendAudit({
        eventType: 'oidc_callback_failed',
        outcome: 'failure',
        requestCorrelationId,
        reasonCode
      });
    } catch {
      console.error('OIDC audit persistence unavailable');
    }
    metrics.increment('auth_oidc_callback_total', { outcome: 'failure', reason: reasonClass(reasonCode) });
    if (reasonCode === 'invalid_state') alerts.emit('oidc_replay_or_state_miss', { reason: 'state_miss' });
    if (reasonCode === 'issuer_mixup') alerts.emit('oidc_issuer_mixup', { reason: 'issuer_mismatch' });
    if (reservationId) await dependencies.rateLimiter?.finalize(reservationId, 'consume');
  }

  function reasonClass(reason: string) {
    if (reason.includes('state')) return 'state';
    if (reason.includes('issuer')) return 'issuer';
    if (reason.includes('decrypt') || reason.includes('integrity')) return 'crypto';
    if (reason.includes('provision')) return 'account';
    return 'validation';
  }

  return {
    failurePath: config.failurePath,

    async startLogin({ returnTo, requestCorrelationId, reauthentication = false, reauthenticationFamilyId,
      invitationToken, recovery = false }) {
      if (reauthentication !== (typeof reauthenticationFamilyId === 'string'
        && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(reauthenticationFamilyId))) {
        throw new Error('OIDC reauthentication requires a trusted session family');
      }
      if (recovery && (reauthentication || invitationToken !== undefined)) throw new Error('Invalid authentication intent');
      if (invitationToken !== undefined && !/^[A-Za-z0-9_-]{43}$/.test(invitationToken)) {
        throw new Error('Invalid invitation');
      }
      const decision = invitationToken
        ? await dependencies.rolloutGate.preflightInvitation(digestSecret(invitationToken))
        : await dependencies.rolloutGate.preflightGlobal();
      if (!decision.allowed) throw new Error('Human authentication rollout denied');
      const normalizedReturnTo = normalizeSafeRelativePath(returnTo, '/', config.returnToPrefixes);
      const id = randomUUID();
      const state = oidc.randomState();
      const nonce = oidc.randomNonce();
      const verifier = oidc.randomPKCECodeVerifier();
      const challenge = await oidc.calculatePKCECodeChallenge(verifier);
      const encryptedVerifier = encryptPkceVerifier(config, id, verifier);

      await store.createTransaction({
        id,
        expiresAt: new Date(Date.now() + LOGIN_TRANSACTION_TTL_MS),
        stateDigest: digest(state),
        nonceDigest: digest(nonce),
        pkceVerifierCiphertext: encryptedVerifier.ciphertext,
        pkceVerifierNonce: encryptedVerifier.nonce,
        pkceVerifierAuthTag: encryptedVerifier.authTag,
        pkceKeyVersion: config.currentPkceKeyVersion,
        issuer: config.issuer,
        clientId: config.clientId,
        redirectUri: config.redirectUri,
        returnTo: normalizedReturnTo,
        recoveryIntent: recovery,
        invitationTokenDigest: invitationToken ? digestSecret(invitationToken) : undefined,
        reauthenticationIntent: reauthentication,
        reauthenticationFamilyId,
        audit: {
          eventType: 'oidc_login_started',
          outcome: 'success',
          requestCorrelationId,
          metadata: { recoveryIntent: recovery, reauthenticationIntent: reauthentication,
            invitationIntent: invitationToken !== undefined }
        }
      });

      return oidc.buildAuthorizationUrl(clientConfiguration, {
        response_type: 'code',
        client_id: config.clientId,
        redirect_uri: config.redirectUri,
        scope: 'openid profile email',
        code_challenge: challenge,
        code_challenge_method: 'S256',
        state,
        nonce,
        max_age: '0',
        ...((reauthentication || recovery) ? { prompt: 'login' } : {})
      });
    },

    async completeCallback({ callbackUrl, requestCorrelationId, ipPrefix = 'unknown' }) {
      const reservation = await dependencies.rateLimiter?.reserve('callback_failure_ip', ipPrefix);
      if (reservation && !reservation.allowed) throw new AuthRateLimitError(reservation.retryAfterSeconds);
      const reservationId = reservation?.reservationId;
      const states = callbackUrl.searchParams.getAll('state');
      if (states.length !== 1 || !states[0] || states[0].length > 512) {
        await appendFailureAudit('invalid_state', requestCorrelationId, reservationId);
        throw new OidcCallbackError();
      }

      const transaction = await store.consumeTransaction(digest(states[0]));
      if (!transaction) {
        await appendFailureAudit('invalid_state', requestCorrelationId, reservationId);
        throw new OidcCallbackError();
      }

      const codes = callbackUrl.searchParams.getAll('code');
      const issuers = callbackUrl.searchParams.getAll('iss');
      if (
        codes.length !== 1
        || !codes[0]
        || codes[0].length > 2048
        || callbackUrl.searchParams.has('error')
        || callbackUrl.searchParams.has('id_token')
        || callbackUrl.searchParams.has('token')
        || callbackUrl.searchParams.has('access_token')
        || issuers.length > 1
        || (authorizationResponseIssuerRequired && issuers.length !== 1)
        || (issuers.length === 1 && issuers[0] !== config.issuer)
        || transaction.issuer !== config.issuer
        || transaction.clientId !== config.clientId
        || transaction.redirectUri !== config.redirectUri
      ) {
        const issuerMismatch = issuers.length === 1 && issuers[0] !== config.issuer;
        await appendFailureAudit(
          issuerMismatch ? 'issuer_mixup' : 'invalid_callback', requestCorrelationId, reservationId
        );
        throw new OidcCallbackError();
      }

      let verifier: string;
      try {
        verifier = decryptPkceVerifier(config, transaction);
      } catch {
        alerts.emit(config.pkceKeys.has(transaction.pkceKeyVersion)
          ? 'crypto_integrity_failure'
          : 'crypto_key_failure', { operation: 'oidc_pkce' });
        await appendFailureAudit('pkce_decryption_failed', requestCorrelationId, reservationId);
        throw new OidcCallbackError();
      }

      try {
        const claims = await exchangeAuthorizationCode(config, exactFetch, keySet, codes[0], verifier);
        if (typeof claims.sub !== 'string' || claims.sub.length === 0 || claims.sub.length > 255) {
          throw new OidcCallbackError();
        }
        if (typeof claims.nonce !== 'string') throw new OidcCallbackError();
        const nonceDigest = digest(claims.nonce);
        if (nonceDigest.length !== transaction.nonceDigest.length || !timingSafeEqual(nonceDigest, transaction.nonceDigest)) {
          throw new OidcCallbackError();
        }
        if (typeof claims.iat !== 'number' || !Number.isSafeInteger(claims.iat)
          || claims.iat > Math.floor(Date.now() / 1000) + OIDC_CLOCK_TOLERANCE_SECONDS
          || claims.iat * 1000 < transaction.createdAt.getTime() - OIDC_CLOCK_TOLERANCE_SECONDS * 1000) {
          throw new OidcCallbackError();
        }
        const authenticationTime = claims.auth_time;
        if (typeof authenticationTime !== 'number' || !Number.isSafeInteger(authenticationTime)
          || authenticationTime > Math.floor(Date.now() / 1000) + OIDC_CLOCK_TOLERANCE_SECONDS
          || authenticationTime > claims.iat + OIDC_CLOCK_TOLERANCE_SECONDS
          || authenticationTime * 1000 < transaction.createdAt.getTime() - OIDC_CLOCK_TOLERANCE_SECONDS * 1000) {
          throw new OidcCallbackError();
        }
        const authenticationMethods = Array.isArray(claims.amr) && claims.amr.length <= 16
          && claims.amr.every((method) => typeof method === 'string' && method.length > 0 && method.length <= 100)
          ? [...new Set(claims.amr)] as string[] : [];
        const assuranceContext = typeof claims.acr === 'string' && claims.acr.length > 0 && claims.acr.length <= 255
          ? claims.acr : null;

        const handoffToken = randomBytes(32).toString('base64url');
        const identity = await store.completeIdentity({
          loginTransactionId: transaction.id,
          issuer: config.issuer,
          subject: claims.sub,
          email: typeof claims.email === 'string' ? claims.email : null,
          emailVerified: claims.email_verified === true,
          authenticatedAt: new Date(authenticationTime * 1000),
          authenticationMethods,
          assuranceContext,
          invitationTokenDigest: transaction.invitationTokenDigest,
          recoveryIntent: transaction.recoveryIntent,
          reauthenticationIntent: transaction.reauthenticationIntent,
          reauthenticationFamilyId: transaction.reauthenticationFamilyId,
          handoffId: randomUUID(),
          handoffDigest: digest(handoffToken),
          handoffExpiresAt: new Date(Date.now() + HANDOFF_TTL_MS),
          audit: {
            eventType: 'oidc_callback_succeeded',
            outcome: 'success',
            requestCorrelationId
          }
        });
        if (!identity) throw new AuditedOidcCallbackError();
        if (reservationId) await dependencies.rateLimiter?.finalize(reservationId, 'release');
        metrics.increment('auth_oidc_callback_total', { outcome: 'success', reason: 'none' });
        return { returnTo: transaction.returnTo, identity, handoffToken };
      } catch (error) {
        if (error instanceof AuditedOidcCallbackError) {
          await appendFailureAudit('access_not_provisioned', requestCorrelationId, reservationId);
          throw new OidcCallbackError();
        }
        if (error instanceof AuthRateLimitError) throw error;
        await appendFailureAudit('oidc_validation_failed', requestCorrelationId, reservationId);
        throw new OidcCallbackError();
      }
    }
  };
}

function oneQueryValue(value: unknown) {
  return typeof value === 'string' ? value : undefined;
}

export function registerOidcRoutes(
  app: FastifyInstance,
  service?: OidcService,
  browserSessionService?: BrowserSessionService,
  browserSessionStore?: BrowserSessionStore,
  humanAdministration?: HumanAdministrationService,
  rateLimiter?: AuthRateLimiter
) {
  if (!service) return;

  const unambiguous = browserSessionStore ? {
    onRequest: async (request: FastifyRequest, reply: FastifyReply) => {
      if (hasBrowserSessionCookie(request.headers.cookie)
        && typeof request.headers.authorization === 'string'
        && /^Bearer egdev_/.test(request.headers.authorization)) {
        await browserSessionStore.recordAmbiguousCredentials({
          requestCorrelationId: request.id,
          userAgent: typeof request.headers['user-agent'] === 'string' ? request.headers['user-agent'] : null
        });
        return reply.header('Cache-Control', 'no-store').status(400).send({ error: 'ambiguous_credentials' });
      }
    }
  } : {};

  app.get('/auth/login', unambiguous, async (request, reply) => {
    reply
      .header('Cache-Control', 'no-store')
      .header('Pragma', 'no-cache')
      .header('Referrer-Policy', 'no-referrer')
      .header('Set-Cookie', CLEARED_HANDOFF_COOKIE);
    try {
      const limited = await rateLimiter?.check('login_ip', requestIpPrefix(request));
      if (limited && !limited.allowed) {
        return reply.header('Retry-After', limited.retryAfterSeconds).status(429).send({ error: 'authentication_temporarily_unavailable' });
      }
      const query = request.query && typeof request.query === 'object'
        ? request.query as Record<string, unknown>
        : {};
      const authorizationUrl = await service.startLogin({
        returnTo: oneQueryValue(query.returnTo),
        requestCorrelationId: request.id
      });
      return reply.redirect(authorizationUrl.toString(), 302);
    } catch {
      return reply.redirect(service.failurePath, 303);
    }
  });

  app.post('/auth/invitations/accept', unambiguous, async (request, reply) => {
    reply.header('Cache-Control', 'no-store').header('Referrer-Policy', 'no-referrer');
    const origin = typeof request.headers.origin === 'string' ? request.headers.origin : null;
    const contentType = typeof request.headers['content-type'] === 'string' ? request.headers['content-type'] : '';
    const body = request.body && typeof request.body === 'object' && !Array.isArray(request.body)
      ? request.body as Record<string, unknown> : {};
    if (!browserSessionStore || origin !== browserSessionStore.publicApplicationOrigin
      || !/^application\/json(?:\s*;\s*charset=[A-Za-z0-9._-]+)?$/i.test(contentType)
      || Object.keys(body).some((key) => !['token', 'returnTo'].includes(key))
      || typeof body.token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(body.token)
      || (body.returnTo !== undefined && typeof body.returnTo !== 'string')) {
      return reply.status(400).send({ error: 'invalid_request' });
    }
    try {
      const ipReservation = await rateLimiter?.reserve('invitation_acceptance_ip', requestIpPrefix(request));
      if (ipReservation && !ipReservation.allowed) {
        return reply.header('Retry-After', ipReservation.retryAfterSeconds).status(429)
          .send({ error: 'authentication_temporarily_unavailable' });
      }
      const invitationDigest = digestSecret(body.token);
      const invitationReservation = await rateLimiter?.reserve(
        'invitation_acceptance_digest', invitationDigest.toString('hex')
      );
      if (invitationReservation && !invitationReservation.allowed) {
        if (ipReservation?.reservationId) await rateLimiter?.finalize(ipReservation.reservationId, 'consume');
        return reply.header('Retry-After', invitationReservation.retryAfterSeconds).status(429)
          .send({ error: 'authentication_temporarily_unavailable' });
      }
      if (ipReservation?.reservationId) await rateLimiter?.finalize(ipReservation.reservationId, 'consume');
      if (invitationReservation?.reservationId) await rateLimiter?.finalize(invitationReservation.reservationId, 'consume');
      const authorizationUrl = await service.startLogin({ invitationToken: body.token,
        returnTo: body.returnTo as string | undefined, requestCorrelationId: request.id });
      return { navigateTo: authorizationUrl.toString() };
    } catch { return reply.status(400).send({ error: 'invalid_request' }); }
  });

  app.get('/auth/recovery', unambiguous, async (request, reply) => {
    reply.header('Cache-Control', 'no-store').header('Pragma', 'no-cache').header('Referrer-Policy', 'no-referrer');
    if (!humanAdministration) return reply.status(503).send({ error: 'authentication_unavailable' });
    if (request.query && typeof request.query === 'object' && Object.keys(request.query).length > 0) {
      return reply.status(400).send({ error: 'invalid_request' });
    }
    try {
      const limited = await rateLimiter?.check('recovery_ip', requestIpPrefix(request));
      if (limited && !limited.allowed) {
        return reply.header('Retry-After', limited.retryAfterSeconds).status(429)
          .send({ error: 'authentication_temporarily_unavailable' });
      }
      const authorizationUrl = await service.startLogin({ requestCorrelationId: request.id, recovery: true });
      const recovery = new URL(humanAdministration.recoveryUrl);
      recovery.search = authorizationUrl.search;
      return reply.redirect(recovery.toString(), 302);
    } catch { return reply.redirect(service.failurePath, 303); }
  });

  app.get('/auth/callback', unambiguous, async (request, reply) => {
    reply.header('Cache-Control', 'no-store').header('Pragma', 'no-cache').header('Referrer-Policy', 'no-referrer');
    try {
      const callbackUrl = new URL(request.url, 'https://egogero.invalid');
      const ipPrefix = requestIpPrefix(request);
      const result = await service.completeCallback({ callbackUrl, requestCorrelationId: request.id, ipPrefix });
      if (browserSessionService) {
        const issued = await browserSessionService.issueFromHandoff({
          handoffToken: result.handoffToken,
          oldSessionToken: parseBrowserSessionCookie(request.headers.cookie) ?? undefined,
          requestCorrelationId: request.id,
          ipPrefix,
          userAgent: typeof request.headers['user-agent'] === 'string' ? request.headers['user-agent'] : null
        });
        if (!issued) throw new OidcCallbackError();
        reply.header('Set-Cookie', [
          browserSessionService.sessionCookie(issued.sessionToken),
          CLEARED_HANDOFF_COOKIE
        ]);
      } else {
        reply.header(
          'Set-Cookie',
          `${HANDOFF_COOKIE}=${result.handoffToken}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${HANDOFF_TTL_MS / 1000}`
        );
      }
      return reply.redirect(result.returnTo, 303);
    } catch (error) {
      reply.header('Set-Cookie', CLEARED_HANDOFF_COOKIE);
      if (error instanceof AuthRateLimitError) {
        return reply.header('Retry-After', error.retryAfterSeconds).status(429).send({ error: 'authentication_temporarily_unavailable' });
      }
      return reply.redirect(service.failurePath, 303);
    }
  });
}
