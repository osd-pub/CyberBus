/*
 * Offline audit-redaction reference fixture; no Logto connection or deployment.
 * Uses the ORIGINAL, UNPATCHED Logto sources at exactly:
 *   4885ab76a96899c3d104841c259e4cf46ce8d48b
 * Original source bytes are checked by SHA-256 before execution. Sources stay
 * outside this repository. Node >=22.13 is required for stripTypeScriptTypes.
 *
 * Reproduce the source cache (only four public source files):
 *   audit_sha=4885ab76a96899c3d104841c259e4cf46ce8d48b
 *   audit_src="/tmp/cyberbus-logto-audit-$audit_sha"
 *   for p in packages/core/src/utils/type.ts \
 *     packages/core/src/utils/sensitive-data.ts \
 *     packages/core/src/middleware/koa-audit-log.ts \
 *     packages/core/src/oidc/extra-token-claims.ts; do
 *     mkdir -p "$audit_src/$(dirname "$p")"
 *     curl --fail --silent --show-error \
 *       "https://raw.githubusercontent.com/logto-io/logto/$audit_sha/$p" \
 *       -o "$audit_src/$p"
 *   done
 * Run from the cyberbus repository root:
 *   node --disable-warning=ExperimentalWarning \
 *     deploy/check-audit-redaction.mjs "$audit_src"
 *
 * Actual type helpers, redactor, LogEntry and koaAuditLog are executed in a VM;
 * imports/exports are removed after Node transforms TS types/parameter fields.
 * Infrastructure such
 * as enum values, ID generation, request metadata, and DB insertion is stubbed.
 * No policy is reimplemented. The issuance source is pinned and its audit
 * write/exclusion statements checked; this is NOT a full issuance integration.
 * Only public fixture credentials are used; no values/seed/error dumps printed.
 *
 * Coverage: structured claim/result/input records passed through LogEntry
 * append/prepend and the final audit insertion filter. Other claims retain
 * their original audit policy. The JWT result itself must stay unredacted.
 * NOT covered: console/worker stdout, App Insights exception serialization,
 * arbitrary string/JSON error messages, a root key outside environmentVariables,
 * reverse proxies, APM, HTTP request/response capture, or client telemetry.
 * Original code still sends the customizer test response to the console UI.
 * Real G1 must inspect ALL logs/exports with the actual deployment settings;
 * these fixtures do not prove that production emits no sensitive information.
 */
import { readFile } from 'node:fs/promises';
import { createHash, webcrypto } from 'node:crypto';
import { stripTypeScriptTypes } from 'node:module';
import { resolve } from 'node:path';
import { TextEncoder } from 'node:util';
import vm from 'node:vm';

const CLAIM = 'https://cyberbus.x.aixgg.com/easytier/credentials/v1';
const SEED_FIELD = 'account_seed_secret_hex';
const MASK = '******';
// Public fixture key, never a production root. No real environment is read.
const TEST_ROOT_HEX = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
const PINNED_FILES = {
  'packages/core/src/utils/type.ts':
    '38114d562c9e69c989e93d0bd48387e19adf1f2844f08179a9502e4fccc0b272',
  'packages/core/src/utils/sensitive-data.ts':
    'ed501fd95dd7bafc8cba93597930c39af97921910d8f5e521cd7d77dea212137',
  'packages/core/src/middleware/koa-audit-log.ts':
    '66e032931e68aa318a47559522eef8276a0fc9a9cf8e8761cc6013c8518f7bef',
  'packages/core/src/oidc/extra-token-claims.ts':
    'de27b17fecef557bcf02e533cd04c0850b9d9c9399720f941e5410ae1967716c',
};

function check(condition) {
  if (!condition) throw new Error('Audit fixture assertion failed');
}
function plain(value) {
  return JSON.parse(JSON.stringify(value));
}
// Source pinning makes this a bounded module loader, not a general TS bundler.
function loadSource(source, bindings, expression) {
  const javascript = stripTypeScriptTypes(source, { mode: 'transform' })
    .replace(/^import\b[\s\S]*?;\s*/gm, '')
    .replace(/^export default /gm, '')
    .replace(/^export /gm, '');
  const realm = vm.createContext({ ...bindings, console: undefined }, {
    codeGeneration: { strings: false, wasm: false },
  });
  return new vm.Script(`${javascript}\n;(${expression});`, {
    filename: 'pinned-logto-audit-fixture.js',
  }).runInContext(realm, { timeout: 1000 });
}

async function main() {
  check(process.argv.length === 3);
  const sourceRoot = resolve(process.argv[2]);
  const sources = Object.fromEntries(await Promise.all(
    Object.entries(PINNED_FILES).map(async ([path, expected]) => {
      const bytes = await readFile(resolve(sourceRoot, path));
      check(createHash('sha256').update(bytes).digest('hex') === expected);
      return [path, bytes.toString('utf8')];
    })
  ));
  const types = loadSource(sources['packages/core/src/utils/type.ts'], {}, '{ isArray, isRecord }');
  const { sanitizeSensitiveDataRecord: sanitize } = loadSource(
    sources['packages/core/src/utils/sensitive-data.ts'], types,
    '{ sanitizeSensitiveDataRecord }'
  );
  const unexpected = () => { throw new Error('Unexpected fixture infrastructure call'); };
  class FixtureRequestError extends Error {}
  const { LogEntry, koaAuditLog } = loadSource(
    sources['packages/core/src/middleware/koa-audit-log.ts'],
    {
      ...types,
      sanitizeSensitiveDataRecord: sanitize,
      stripNullCharactersFromString: loadSource(
        sources['packages/core/src/utils/sensitive-data.ts'], types,
        'stripNullCharactersFromString'
      ),
      LogResult: { Success: 'Success', Error: 'Error' },
      generateStandardId: () => 'public-audit-fixture-id',
      conditional: (value) => value || undefined,
      pick: unexpected,
      RequestError: FixtureRequestError,
      getInjectedHeaderValues: () => undefined,
      sanitizeError: unexpected,
      UAParser: unexpected,
    },
    '{ LogEntry, koaAuditLog }'
  );

  const hookSource = await readFile(new URL('./logto-user-token.js', import.meta.url), 'utf8');
  const hook = new vm.Script(`${hookSource}\n;getCustomJwtClaims;`).runInContext(
    vm.createContext({ crypto: webcrypto, TextEncoder, URL, console: undefined }),
    { timeout: 1000 }
  );
  const input = {
    token: {
      aud: 'https://api.example.test/easytier', scope: 'network:join',
      clientId: 'public-desktop', accountId: 'public-account',
      kind: 'AccessToken', gty: 'authorization_code',
      jti: 'public-jti-marker',
    },
    context: {
      user: { id: 'public-account' },
      application: { id: 'public-desktop', type: 'Native' },
    },
    environmentVariables: {
      ET_ISSUER: 'https://logto.example.test/oidc',
      ET_RESOURCE: 'https://api.example.test/easytier',
      ET_ROOT_KEY_HEX: TEST_ROOT_HEX,
      ET_PRODUCTS_JSON: JSON.stringify([
        { productId: 'public-product', nativeClientIds: ['public-desktop'] },
      ]),
      ET_CREDENTIAL_EPOCH: '1', ET_CONFIG_VERSION: 'public-v1',
    },
  };
  const issued = plain(await hook(input));
  check(issued[CLAIM] && /^[0-9a-f]{64}$/u.test(issued[CLAIM][SEED_FIELD]));
  const publicSeed = issued[CLAIM][SEED_FIELD];
  const before = JSON.stringify(issued);
  let passes = 0;
  let failures = 0;
  async function test(name, run) {
    try {
      await run();
      passes += 1;
    } catch {
      failures += 1;
      console.error(`FAIL: ${name}`);
    }
  }
  function noCredentials(value) {
    const serialized = JSON.stringify(value);
    check(!serialized.includes(publicSeed));
    check(!serialized.includes(TEST_ROOT_HEX));
    check(!serialized.includes('public-jti-marker'));
  }

  await test('four original source SHA-256 prechecks passed', () => {
    check(Object.keys(sources).length === 4);
  });
  await test('original issuance writes raw result but excludes script and environment', () => {
    const issuance = sources['packages/core/src/oidc/extra-token-claims.ts'];
    check(issuance.includes('ctx.prependAllLogEntries({ customTokenClaims: result });'));
    check(issuance.includes(
      'const { script: _script, environmentVariables: _environmentVariables, ...logPayload } = payload;'
    ));
    check(issuance.includes('payload: logPayload,'));
  });
  await test('legacy naming reproduces the original audit exposure without printing it', () => {
    // Intentional negative control only; the hook no longer emits these keys.
    const legacy = sanitize({ customTokenClaims: {
      'https://cyberbus.example/easytier/v1': { account_seed_hex: publicSeed },
    } });
    check(legacy.customTokenClaims['https://cyberbus.example/easytier/v1'].account_seed_hex === publicSeed);
  });
  await test('credentials namespace masks the entire actual hook claim', () => {
    const filtered = sanitize({ customTokenClaims: issued });
    check(filtered.customTokenClaims[CLAIM] === MASK);
    noCredentials(filtered);
  });
  await test('secret seed leaf is masked independently outside its namespace', () => {
    const filtered = sanitize({ extracted: { [SEED_FIELD]: publicSeed, config_version: 'public-v1' } });
    check(filtered.extracted[SEED_FIELD] === MASK);
    check(filtered.extracted.config_version === 'public-v1');
    noCredentials(filtered);
  });
  await test('normalization removes NUL underscores hyphens and lowercases keys', () => {
    const nul = String.fromCodePoint(0);
    const namespace = CLAIM.toUpperCase().replace('CREDENTIALS', `CRED${nul}ENTIALS`);
    const filtered = sanitize({
      [namespace]: issued[CLAIM],
      [`ACCOUNT-SEED_${nul}SECRET_HEX`]: publicSeed,
    });
    check(filtered[namespace.replaceAll(nul, '')] === MASK);
    check(filtered['ACCOUNT-SEED_SECRET_HEX'] === MASK);
    noCredentials(filtered);
  });
  await test('recursive records and arrays mask namespace and extracted seed', () => {
    const filtered = sanitize({ items: [
      { [CLAIM]: issued[CLAIM] }, [{ [SEED_FIELD]: publicSeed }],
    ] });
    check(filtered.items[0][CLAIM] === MASK);
    check(filtered.items[1][0][SEED_FIELD] === MASK);
    noCredentials(filtered);
  });
  await test('unrelated business claims and client id retain existing audit behavior', () => {
    const filtered = sanitize({ customTokenClaims: {
      ...issued,
      'https://example.test/business': { plan: 'public-plan', enabled: true },
    } });
    check(filtered.customTokenClaims.client_id === 'public-desktop');
    check(filtered.customTokenClaims['https://example.test/business'].plan === 'public-plan');
    check(filtered.customTokenClaims['https://example.test/business'].enabled === true);
    noCredentials(filtered);
  });
  await test('raw internal token and bearer token fields are masked', () => {
    const filtered = sanitize({ payload: { token: input.token }, access_token: 'public-bearer' });
    check(filtered.payload.token === MASK && filtered.access_token === MASK);
    noCredentials(filtered);
  });
  await test('script and sensitive environment objects are omitted', () => {
    const filtered = sanitize({ payload: {
      ...input, script: 'public fixture script text',
      environmentVariablesBackup: input.environmentVariables,
    } });
    check(!('script' in filtered.payload));
    check(!('environmentVariables' in filtered.payload));
    check(!('environmentVariablesBackup' in filtered.payload));
    noCredentials(filtered);
  });
  await test('real LogEntry append redacts inputs before storing its context', () => {
    const entry = new LogEntry('CustomJwt.AccessToken');
    entry.append({ payload: { ...input, script: 'public script' } });
    check(entry.payload.payload.token === MASK);
    check(!('environmentVariables' in entry.payload.payload));
    check(!('script' in entry.payload.payload));
    noCredentials(entry.payload);
  });
  await test('real LogEntry prepend masks result without mutating issuance result', () => {
    const entry = new LogEntry('CustomJwt.AccessToken');
    entry.prepend({ customTokenClaims: issued });
    check(entry.payload.customTokenClaims[CLAIM] === MASK);
    noCredentials(entry.payload);
    check(JSON.stringify(issued) === before);
  });
  await test('real audit middleware sanitizes every stored entry at insertion', async () => {
    const inserted = [];
    const middleware = koaAuditLog({ logs: {
      insertLog: async (record) => { inserted.push(plain(record)); },
      insertLogIfNotExists: unexpected,
    } });
    const ctx = { request: { ip: '192.0.2.1', headers: {} } };
    await middleware(ctx, async () => {
      const first = ctx.createLog('CustomJwt.AccessToken');
      const second = ctx.createLog('Interaction.SignIn');
      first.append({ payload: { ...input, script: 'public script' } });
      ctx.prependAllLogEntries({ customTokenClaims: issued });
      // Deliberately bypass append/prepend to exercise the final filter too.
      second.payload.direct = {
        [CLAIM]: issued[CLAIM], [SEED_FIELD]: publicSeed,
        token: input.token, environmentVariables: input.environmentVariables,
      };
    });
    check(inserted.length === 2);
    for (const { payload } of inserted) {
      check(payload.customTokenClaims[CLAIM] === MASK);
      check(payload.customTokenClaims.client_id === 'public-desktop');
      noCredentials(payload);
    }
    check(inserted[1].payload.direct[CLAIM] === MASK);
    check(inserted[1].payload.direct[SEED_FIELD] === MASK);
    check(inserted[1].payload.direct.token === MASK);
    check(!('environmentVariables' in inserted[1].payload.direct));
  });
  await test('negative control documents unparsed string and bare root key limits', () => {
    const filtered = sanitize({
      message: JSON.stringify({ [SEED_FIELD]: publicSeed }),
      ET_ROOT_KEY_HEX: TEST_ROOT_HEX,
    });
    // The original redactor is key-based; it does not scan string contents and
    // a bare ET_ROOT_KEY_HEX key lacks a sensitive fragment. Do not log either.
    check(filtered.message.includes(publicSeed));
    check(filtered.ET_ROOT_KEY_HEX === TEST_ROOT_HEX);
  });
  await test('audit redaction leaves final JWT credentials intact', () => {
    check(JSON.stringify(issued) === before);
    check(issued[CLAIM][SEED_FIELD] === publicSeed);
  });

  if (failures > 0) {
    console.error(`FAIL: ${failures} audit checks; PASS: ${passes} audit checks`);
    process.exitCode = 1;
  } else {
    console.log(`PASS: ${passes} audit checks`);
  }
}

await main().catch(() => {
  // Avoid dumping source/fixture values, arguments, or errors on precheck failure.
  console.error('FAIL: audit fixture setup or pinned source precheck');
  process.exitCode = 1;
});
