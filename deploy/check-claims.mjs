/*
 * Run: node deploy/check-claims.mjs
 * Bounded, offline reference fixtures only; NO real Logto connection, secrets,
 * environment reads, or production seed output. Fixtures do not establish real
 * Logto integration, final JWT contents, SDK verification, or denial semantics.
 * The target release must support the supplied WebCrypto/internal-token contract
 * and trusted context.application.type. Deployment also requires Logto's
 * blockIssuanceOnError=true and SDK rejection of missing/invalid claims.
 */
import { readFile } from 'node:fs/promises';
import { createHmac, webcrypto } from 'node:crypto';
import { Buffer } from 'node:buffer';
import { TextEncoder } from 'node:util';
import vm from 'node:vm';

// PUBLIC TEST ROOT. Deliberately predictable; NEVER deploy this as a secret.
const TEST_ROOT_HEX = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
const CLAIM = 'https://cyberbus.x.aixgg.com/easytier/credentials/v1';
const DENIAL = 'EasyTier credential issuance denied';
const PRODUCTS = [
  {
    productId: 'fixture-product',
    nativeClientIds: ['fixture-desktop', 'fixture-mobile'],
    browserClientIds: ['fixture-web'],
  },
  { productId: 'fixture-other-product', nativeClientIds: ['fixture-other-client'] },
];
const ENVIRONMENT = {
  ET_ISSUER: 'https://logto.example.test/oidc',
  ET_RESOURCE: 'https://api.example.test/easytier',
  ET_ROOT_KEY_HEX: TEST_ROOT_HEX,
  ET_PRODUCTS_JSON: JSON.stringify(PRODUCTS),
  ET_CREDENTIAL_EPOCH: '9007199254740993', // Above Number's exact integer range.
  ET_CONFIG_VERSION: 'fixture-v1',
};

const source = await readFile(new URL('./logto-user-token.js', import.meta.url), 'utf8');
// No fetch, console, btoa, process, Buffer, require, or import in the hook realm.
// Node's VM here checks portability; it is not a sandbox for untrusted programs.
function loadHook(cryptoApi = webcrypto) {
  const realm = vm.createContext(
    { crypto: cryptoApi, TextEncoder, URL, console: undefined },
    { codeGeneration: { strings: false, wasm: false } }
  );
  return new vm.Script(`${source}\n;getCustomJwtClaims;`, {
    filename: 'logto-user-token.js',
  }).runInContext(realm, { timeout: 1000 });
}
const getClaims = loadHook();

function fixture({
  accountId = 'fixture-account',
  clientId = 'fixture-desktop',
  applicationType = 'Native',
  env = {},
} = {}) {
  return {
    token: {
      aud: ENVIRONMENT.ET_RESOURCE,
      scope: 'openid network:join profile',
      clientId,
      accountId,
      kind: 'AccessToken',
      gty: 'authorization_code',
    },
    context: {
      user: { id: accountId },
      application: { id: clientId, type: applicationType },
    },
    environmentVariables: { ...ENVIRONMENT, ...env },
  };
}

// Independent implementation: Node createHmac, Buffer's UTF-8 encoder and
// writeUInt32BE, incremental HMAC updates; no hook helpers or WebCrypto reuse.
function reference(input, productId) {
  const hmac = createHmac('sha256', Buffer.from(input.environmentVariables.ET_ROOT_KEY_HEX, 'hex'));
  for (const value of [
    '/seed/v1',
    input.environmentVariables.ET_ISSUER,
    input.token.accountId,
    productId,
    input.environmentVariables.ET_CREDENTIAL_EPOCH,
  ]) {
    const bytes = Buffer.from(value, 'utf8');
    const length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.length);
    hmac.update(length);
    hmac.update(bytes);
  }
  return hmac.digest('hex');
}

let passes = 0;
let failures = 0;
function check(condition) {
  // Never put compared values into an assertion message or error report.
  if (!condition) throw new Error('Fixture assertion failed');
}
async function test(name, run) {
  try {
    await run();
    passes += 1;
  } catch {
    failures += 1;
    console.error(`FAIL: ${name}`); // Only a fixed test name, never input/results.
  }
}
async function claims(input = fixture(), api) {
  const result = await getClaims({ ...input, api });
  // Copy across VM realms for consistent comparisons of plain JSON output.
  return JSON.parse(JSON.stringify(result));
}
async function rejects(input, mode = 'absent') {
  let called = 0;
  const sentinel = new Error(DENIAL);
  const api = mode === 'absent' ? undefined : {
    denyAccess(message) {
      called += 1;
      check(message === DENIAL);
      if (mode === 'throws') throw sentinel;
    },
  };
  let error;
  try {
    await claims(input, api);
  } catch (caught) {
    error = caught;
  }
  check(error !== undefined && error.message === DENIAL);
  check(called === (mode === 'absent' ? 0 : 1));
  if (mode === 'throws') check(error === sentinel);
}
function seed(result) {
  return result[CLAIM].account_seed_secret_hex;
}

await test('exact claim shape and independent HMAC reference', async () => {
  const input = fixture();
  const before = JSON.stringify(input);
  const result = await claims(input);
  const expected = {
    client_id: input.token.clientId,
    [CLAIM]: {
      version: 1,
      product_id: PRODUCTS[0].productId,
      credential_epoch: ENVIRONMENT.ET_CREDENTIAL_EPOCH,
      account_seed_secret_hex: reference(input, PRODUCTS[0].productId),
      max_devices: 256,
      virtual_cidr: '10.144.0.0/20',
      control_port: 11000,
      config_version: 'fixture-v1',
    },
  };
  check(JSON.stringify(result) === JSON.stringify(expected));
  check(/^[0-9a-f]{64}$/u.test(seed(result)));
  check(JSON.stringify(input) === before);
  check(['sub', 'iss', 'aud', 'exp'].every((key) => !(key in result)));
});
await test('same account and product across Native clients', async () => {
  const desktop = await claims();
  const mobile = await claims(fixture({ clientId: 'fixture-mobile' }));
  check(seed(desktop) === seed(mobile));
  check(mobile.client_id === 'fixture-mobile');
});
await test('same account and product across Native and SPA clients', async () => {
  const desktop = await claims();
  const web = await claims(
    fixture({
      clientId: 'fixture-web',
      applicationType: 'SPA',
    }),
  );
  check(seed(desktop) === seed(web));
  check(web.client_id === 'fixture-web');
});
await test('browser-only product needs no Native client', async () => {
  const products = [{
    productId: 'fixture-web-only-product',
    nativeClientIds: [],
    browserClientIds: ['fixture-web-only-client'],
  }];
  const input = fixture({
    clientId: 'fixture-web-only-client',
    applicationType: 'SPA',
    env: { ET_PRODUCTS_JSON: JSON.stringify(products) },
  });
  const result = await claims(input);
  check(result[CLAIM].product_id === products[0].productId);
  check(seed(result) === reference(input, products[0].productId));
});
await test('refresh and incidental token metadata keep seed stable', async () => {
  const initial = await claims();
  for (const gty of ['refresh_token', 'authorization_code refresh_token']) {
    const input = fixture();
    Object.assign(input.token, { gty, jti: 'new-fixture-token', exp: 1234567890 });
    check(seed(await claims(input)) === seed(initial));
  }
});
await test('account product epoch and issuer isolate namespaces', async () => {
  const inputs = [
    [fixture(), PRODUCTS[0].productId],
    [fixture({ accountId: 'fixture-other-account' }), PRODUCTS[0].productId],
    [fixture({ clientId: 'fixture-other-client' }), PRODUCTS[1].productId],
    [fixture({ env: { ET_CREDENTIAL_EPOCH: '9007199254740994' } }), PRODUCTS[0].productId],
    [fixture({ env: { ET_ISSUER: 'https://other.example.test/oidc' } }), PRODUCTS[0].productId],
  ];
  const seeds = [];
  for (const [input, product] of inputs) {
    const actual = seed(await claims(input));
    check(actual === reference(input, product));
    seeds.push(actual);
  }
  check(new Set(seeds).size === inputs.length);
});
await test('configuration version does not rotate credentials', async () => {
  const changed = await claims(fixture({ env: { ET_CONFIG_VERSION: 'fixture-v2' } }));
  check(seed(changed) === seed(await claims()));
  check(changed[CLAIM].config_version === 'fixture-v2');
});
for (const [index, value] of [' ', '~', ' ~v1', 'x'.repeat(64)].entries()) {
  await test(`printable ASCII config version boundary ${index + 1}`, async () => {
    const result = await claims(fixture({ env: { ET_CONFIG_VERSION: value } }));
    check(result[CLAIM].config_version === value);
  });
}
await test('UTF-8 byte lengths preserve Unicode and normalization distinctions', async () => {
  const outputs = [];
  for (const accountId of ['fixture-账号-😀', 'fixture-é', 'fixture-e\u0301']) {
    const products = [{ productId: '产品-😀', nativeClientIds: ['fixture-desktop'] }];
    const input = fixture({ accountId, env: { ET_PRODUCTS_JSON: JSON.stringify(products) } });
    const actual = seed(await claims(input));
    check(actual === reference(input, products[0].productId));
    outputs.push(actual);
  }
  check(new Set(outputs).size === outputs.length);
});
await test('length prefixes disambiguate adjacent fields', async () => {
  const outputs = [];
  for (const [accountId, productId] of [['fixture-a', 'bc'], ['fixture-ab', 'c']]) {
    const input = fixture({ accountId, env: {
      ET_PRODUCTS_JSON: JSON.stringify([{ productId, nativeClientIds: ['fixture-desktop'] }]),
    } });
    const actual = seed(await claims(input));
    check(actual === reference(input, productId));
    outputs.push(actual);
  }
  check(outputs[0] !== outputs[1]);
});
for (const epoch of ['0', '1', '18446744073709551615']) {
  await test(`canonical epoch boundary ${epoch}`, async () => {
    const input = fixture({ env: { ET_CREDENTIAL_EPOCH: epoch } });
    const result = await claims(input);
    check(result[CLAIM].credential_epoch === epoch);
    check(seed(result) === reference(input, PRODUCTS[0].productId));
  });
}
await test('uppercase root hex decodes raw bytes', async () => {
  const input = fixture({ env: { ET_ROOT_KEY_HEX: TEST_ROOT_HEX.toUpperCase() } });
  check(seed(await claims(input)) === seed(await claims()));
});
await test('scope uses whitespace-delimited exact membership', async () => {
  const input = fixture();
  input.token.scope = ' \topenid\r\nnetwork:join\tprofile ';
  check(seed(await claims(input)) === seed(await claims()));
});
await test('optional identity aliases may agree', async () => {
  const input = fixture();
  Object.assign(input.token, {
    sub: input.token.accountId, client_id: input.token.clientId, azp: input.token.clientId,
  });
  input.context.user.sub = input.token.accountId;
  check(seed(await claims(input)) === seed(await claims()));
});
await test('application type is mandatory even without application id', async () => {
  const input = fixture();
  delete input.context.application.id;
  check(seed(await claims(input)) === seed(await claims()));
});
await test('untrusted request and custom data cannot select namespace', async () => {
  const input = fixture();
  input.context.request = { accountId: 'attacker', clientId: 'fixture-other-client', productId: 'evil' };
  input.context.user.customData = { productId: 'evil', account_seed_secret_hex: 'evil' };
  input.token.product_id = 'evil';
  check(seed(await claims(input)) === seed(await claims()));
});

const deniedCases = [
  ['missing scope', (x) => { delete x.token.scope; }],
  ['empty scope', (x) => { x.token.scope = ''; }],
  ['wrong scope', (x) => { x.token.scope = 'openid network:join:admin'; }],
  ['array scope', (x) => { x.token.scope = ['network:join']; }],
  ['unknown client', (x) => { x.token.clientId = 'unknown'; x.context.application.id = 'unknown'; }],
  ['missing client', (x) => { delete x.token.clientId; }],
  ['M2M kind', (x) => { x.token.kind = 'ClientCredentials'; }],
  ['unknown kind', (x) => { x.token.kind = 'IdToken'; }],
  ['missing kind', (x) => { delete x.token.kind; }],
  ['client credentials grant', (x) => { x.token.gty = 'client_credentials'; }],
  ['combined client credentials grant', (x) => { x.token.gty = 'client_credentials refresh_token'; }],
  ['missing grant', (x) => { delete x.token.gty; }],
  ['array grant', (x) => { x.token.gty = ['authorization_code']; }],
  ['missing account', (x) => { delete x.token.accountId; }],
  ['empty account', (x) => { x.token.accountId = ''; x.context.user.id = ''; }],
  ['numeric account', (x) => { x.token.accountId = 123; x.context.user.id = 123; }],
  ['conflicting subject', (x) => { x.token.sub = 'other'; }],
  ['null subject', (x) => { x.token.sub = null; }],
  ['conflicting user subject', (x) => { x.context.user.sub = 'other'; }],
  ['conflicting client alias', (x) => { x.token.client_id = 'fixture-mobile'; }],
  ['conflicting azp', (x) => { x.token.azp = 'fixture-mobile'; }],
  ['missing context', (x) => { delete x.context; }],
  ['missing user', (x) => { delete x.context.user; }],
  ['missing user id', (x) => { delete x.context.user.id; }],
  ['user identity conflict', (x) => { x.context.user.id = 'other'; }],
  ['missing application', (x) => { delete x.context.application; }],
  ['missing application type', (x) => { delete x.context.application.type; }],
  ['non-Native application', (x) => { x.context.application.type = 'Traditional'; }],
  ['lowercase Native', (x) => { x.context.application.type = 'native'; }],
  ['M2M application', (x) => { x.context.application.type = 'MachineToMachine'; }],
  ['SPA client with Native type', (x) => {
    x.token.clientId = 'fixture-web';
    x.context.application.id = x.token.clientId;
    x.context.application.type = 'Native';
  }],
  ['Native client with SPA type', (x) => { x.context.application.type = 'SPA'; }],
  ['browser client missing application type', (x) => {
    x.token.clientId = 'fixture-web';
    x.context.application.id = x.token.clientId;
    delete x.context.application.type;
  }],
  ['application id conflict', (x) => { x.context.application.id = 'fixture-mobile'; }],
  ['target audience array', (x) => { x.token.aud = [ENVIRONMENT.ET_RESOURCE]; }],
  ['mixed audience array', (x) => { x.token.aud = ['other', ENVIRONMENT.ET_RESOURCE]; }],
  ['empty audience array', (x) => { x.token.aud = []; }],
  ['empty string in audience array', (x) => { x.token.aud = ['other', '']; }],
  ['null in audience array', (x) => { x.token.aud = ['other', null]; }],
  ['number in audience array', (x) => { x.token.aud = ['other', 123]; }],
  ['object in audience array', (x) => { x.token.aud = ['other', { resource: ENVIRONMENT.ET_RESOURCE }]; }],
  ['nested audience array', (x) => { x.token.aud = ['other', [ENVIRONMENT.ET_RESOURCE]]; }],
  ['sparse audience array', (x) => { x.token.aud = ['other']; x.token.aud.length = 2; }],
  ['object audience', (x) => { x.token.aud = { resource: ENVIRONMENT.ET_RESOURCE }; }],
  ['numeric audience', (x) => { x.token.aud = 123; }],
  ['boolean audience', (x) => { x.token.aud = false; }],
  ['missing environment', (x) => { delete x.environmentVariables; }],
  ['missing resource pin', (x) => { delete x.environmentVariables.ET_RESOURCE; }],
  ['array resource pin', (x) => { x.environmentVariables.ET_RESOURCE = [ENVIRONMENT.ET_RESOURCE]; }],
  ['lone surrogate account', (x) => { x.token.accountId = '\ud800'; x.context.user.id = '\ud800'; }],
];
for (const [name, mutate] of deniedCases) {
  await test(`denies ${name}`, async () => {
    const input = fixture();
    mutate(input);
    await rejects(input);
  });
}

const invalidEnvironments = {
  ET_ROOT_KEY_HEX: [undefined, '', '00'.repeat(31), '00'.repeat(33), 'gg'.repeat(32),
    ` ${TEST_ROOT_HEX}`, `${TEST_ROOT_HEX}\n`, `0x${TEST_ROOT_HEX}`, 123],
  ET_CREDENTIAL_EPOCH: [undefined, '', '00', '01', '-1', '+1', '1.0', '1e3', ' 1', '1\n',
    '18446744073709551616', '999999999999999999999', 1],
  // All C0 controls (including trailing LF/CR) and DEL must be rejected.
  ET_CONFIG_VERSION: [undefined, '', 'x'.repeat(65), '版本', 1,
    ...Array.from({ length: 32 }, (_, code) => `v${String.fromCharCode(code)}`), 'v\x7f'],
  ET_ISSUER: [undefined, '', 'http://logto.example.test/oidc',
    'https://logto.example.test/oidc/', 'https://logto.example.test',
    'https://user:secret@logto.example.test/oidc', 'https://logto.example.test/oidc?x=1',
    'https://logto.example.test/oidc#x', 'https://logto.example.test/oidc?',
    'https://logto.example.test/oidc#', 'https://LOGTO.example.test/oidc',
    'https://logto.example.test:443/oidc', ' https://logto.example.test/oidc',
    'https://logto.example.test/a/../oidc'],
  ET_PRODUCTS_JSON: [undefined, '', '{', '{}', 'null', '[]', JSON.stringify([null]),
    JSON.stringify([{ productId: '', nativeClientIds: ['fixture-desktop'] }]),
    JSON.stringify([{ productId: 'p', nativeClientIds: [] }]),
    JSON.stringify([{ productId: 'p', nativeClientIds: [], browserClientIds: [] }]),
    JSON.stringify([{ productId: 'p', nativeClientIds: 'fixture-desktop' }]),
    JSON.stringify([{ productId: 'p', nativeClientIds: ['fixture-desktop', 'fixture-desktop'] }]),
    JSON.stringify([{ productId: 'p', nativeClientIds: ['fixture-desktop', ''] }]),
    JSON.stringify([{ productId: 'p', nativeClientIds: [123] }]),
    JSON.stringify([{ productId: 'p', nativeClientIds: ['fixture-desktop'] },
      { productId: 'q', nativeClientIds: ['fixture-desktop'] }]),
    JSON.stringify([{ productId: 'p', nativeClientIds: ['fixture-desktop'] },
      { productId: 'p', nativeClientIds: ['fixture-mobile'] }]),
    JSON.stringify([{ productId: 'p', nativeClientIds: ['fixture-desktop'], browserClientIds: 'fixture-web' }]),
    JSON.stringify([{ productId: 'p', nativeClientIds: ['fixture-desktop'], browserClientIds: [] }]),
    JSON.stringify([{ productId: 'p', nativeClientIds: ['fixture-desktop'], browserClientIds: ['fixture-web', 'fixture-web'] }]),
    JSON.stringify([{ productId: 'p', nativeClientIds: ['fixture-desktop'], browserClientIds: ['fixture-desktop'] }]),
    JSON.stringify([{ productId: 'p', nativeClientIds: ['fixture-desktop'], browserClientIds: [123] }]),
    JSON.stringify([{ productId: 'p', nativeClientIds: ['fixture-desktop'], browserClientIds: ['fixture-web'] },
      { productId: 'q', nativeClientIds: ['fixture-other'], browserClientIds: ['fixture-web'] }]),
    JSON.stringify([{ productId: '\udc00', nativeClientIds: ['fixture-desktop'] }])],
};
for (const [variable, values] of Object.entries(invalidEnvironments)) {
  for (const [index, value] of values.entries()) {
    await test(`denies invalid ${variable} case ${index + 1}`, async () => {
      await rejects(fixture({ env: { [variable]: value } }));
    });
  }
}
for (const mode of ['throws', 'returns']) {
  await test(`api.denyAccess ${mode} still rejects`, async () => {
    const input = fixture();
    input.token.scope = '';
    await rejects(input, mode);
  });
}
await test('runtime without WebCrypto rejects the target', async () => {
  const hook = loadHook(null);
  let error;
  try {
    await hook(fixture());
  } catch (caught) {
    error = caught;
  }
  check(error !== undefined && error.message === DENIAL);
});
await test('crypto failure is sanitized and denyAccess returning still rejects', async () => {
  const hook = loadHook({ subtle: {
    async importKey() { throw new Error('Do not expose this runtime error detail'); },
  } });
  let called = 0;
  let error;
  const input = fixture();
  input.api = { denyAccess(message) { check(message === DENIAL); called += 1; } };
  try {
    await hook(input);
  } catch (caught) {
    error = caught;
  }
  check(error !== undefined && error.message === DENIAL && called === 1);
});
for (const form of ['missing', 'undefined', 'null']) {
  await test(`opaque user token with ${form} audience returns empty unchanged`, async () => {
    // A no-resource OIDC request can issue an opaque user access token. Its
    // internal token still has accountId/clientId/kind/gty, but has no API aud
    // or network:join scope. Application context is irrelevant on this path.
    const input = fixture();
    delete input.token.aud;
    if (form === 'undefined') input.token.aud = undefined;
    if (form === 'null') input.token.aud = null;
    input.token.scope = 'openid offline_access profile';
    delete input.context.application;
    // No resource also bypasses invalid/missing target configuration.
    delete input.environmentVariables;
    const before = JSON.stringify(input);
    const hook = loadHook(null);
    input.api = { denyAccess() { throw new Error('Unexpected denial'); } };
    check(JSON.stringify(await hook(input)) === '{}');
    delete input.api;
    check(JSON.stringify(input) === before);
  });
}
await test('non-target string audience returns empty before target-specific checks', async () => {
  const input = {
    token: { aud: 'https://api.example.test/other', kind: 'ClientCredentials' },
    environmentVariables: { ET_RESOURCE: ENVIRONMENT.ET_RESOURCE, ET_ROOT_KEY_HEX: 'invalid' },
  };
  const api = { denyAccess() { throw new Error('Unexpected denial'); } };
  check(JSON.stringify(await claims(input, api)) === '{}');
});
await test('well-formed arrays containing only non-target audiences return empty', async () => {
  for (const aud of [['other'], ['other', 'another']]) {
    const input = {
      token: { aud, kind: 'AccessToken', scope: 'openid' },
      environmentVariables: { ET_RESOURCE: ENVIRONMENT.ET_RESOURCE },
    };
    const before = JSON.stringify(input);
    const api = { denyAccess() { throw new Error('Unexpected denial'); } };
    check(JSON.stringify(await claims(input, api)) === '{}');
    check(JSON.stringify(input) === before);
  }
});
await test('audience matching is exact without prefix or URL normalization', async () => {
  for (const aud of ['', `${ENVIRONMENT.ET_RESOURCE}/`, `${ENVIRONMENT.ET_RESOURCE}-other`,
    ENVIRONMENT.ET_RESOURCE.toUpperCase(), ` ${ENVIRONMENT.ET_RESOURCE}`]) {
    const input = fixture();
    input.token.aud = aud;
    check(JSON.stringify(await claims(input)) === '{}');
  }
});

if (failures > 0) {
  console.error(`FAIL: ${failures} checks; PASS: ${passes} checks`);
  process.exitCode = 1;
} else {
  console.log(`PASS: ${passes} checks`);
}
