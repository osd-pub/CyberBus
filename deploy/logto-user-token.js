/*
 * Paste this entire file into self-hosted Logto Custom JWT > User access token.
 * Reference contract: the supplied create-script.mdx Runtime APIs snapshot and
 * jwt-customizer.ts sources; this does not establish support in older releases.
 * The deployed version MUST expose Web Crypto, TextEncoder, URL, and trusted
 * context.application (type exactly "Native"). Missing application data denies
 * this resource. token is oidc-provider's internal token, not the final JWT;
 * accountId/clientId are authoritative here, and sub need not be present yet.
 *
 * Set blockIssuanceOnError=true in Logto's external customizer configuration.
 * The SDK MUST verify signature, pinned exact issuer/resource, expiry, scope,
 * allowed client_id (and azp consistency), and this complete versioned claim;
 * missing/invalid/unknown claims or config versions MUST disable network join.
 * Local fixtures do not replace real issuance/refresh/denial integration tests.
 *
 * Configure these SIX hook environment variables on the server only:
 * ET_ISSUER: canonical pinned HTTPS issuer ending exactly in /oidc, no trailing
 *   slash, userinfo, query, or fragment; use the same exact value in the SDK.
 * ET_RESOURCE: exact nonempty target API resource identifier (no normalization).
 * ET_ROOT_KEY_HEX: secret independent 32-byte root key, exactly 64 hex digits.
 * ET_PRODUCTS_JSON: JSON array of {"productId":"...","nativeClientIds":["..."]};
 *   products and clients must be unique, with every client in just one product.
 *   Verify these configured clients really are Native in this Logto deployment.
 * ET_CREDENTIAL_EPOCH: canonical u64 decimal STRING, from 0 to
 *   18446744073709551615 inclusive, with no leading zero except "0" itself.
 * ET_CONFIG_VERSION: 1..64 printable ASCII characters (0x20..0x7e);
 *   control characters, including NUL and DEL, are forbidden.
 *
 * Never expose the root key to an SDK. The returned seed is also a credential:
 * do not log hook inputs/results, tokens, or seeds, or use a real root key in
 * the console test panel. Keep production seed material out of telemetry.
 * The claim namespace intentionally contains "credentials" and the seed field
 * contains "secret": Logto 4885ab76a96899c3d104841c259e4cf46ce8d48b's original
 * audit redactor masks the whole claim and independently masks the seed field.
 * This only covers structured records passed through that redactor, not every
 * log/telemetry sink. Real G1 must inspect all logs; see check-audit-redaction.mjs.
 */
const getCustomJwtClaims = async ({ token, context, environmentVariables, api }) => {
  // Constant error text never includes identities, configuration, or secrets.
  const deny = () => {
    if (api && typeof api.denyAccess === 'function') {
      api.denyAccess('EasyTier credential issuance denied');
    }
    // Also fail closed on versions without api, or if denyAccess returns.
    throw new Error('EasyTier credential issuance denied');
  };
  const isRecord = (value) =>
    value !== null && typeof value === 'object' && !Array.isArray(value);
  const nonemptyString = (value) => typeof value === 'string' && value.length > 0;

  if (!isRecord(token)) return deny();
  // Internal tokens without a resource can be opaque user tokens. This global
  // customizer leaves them alone, including on versions representing no aud as
  // null. No target-specific context, configuration, or crypto is needed.
  const audience = token.aud;
  if (audience === undefined || audience === null) return {};
  if (!isRecord(environmentVariables)) return deny();
  const resource = environmentVariables.ET_RESOURCE;
  if (!nonemptyString(resource)) return deny();
  // Logto's internal schema also permits string[] aud. A nonempty, well-formed
  // list of only other resources is out of scope. Target issuance in this
  // deployment MUST use an exact scalar string: never bypass target checks
  // because the target is hidden in a list. Empty/malformed lists are denied.
  if (Array.isArray(audience)) {
    if (audience.length === 0) return deny();
    for (const item of audience) {
      if (!nonemptyString(item) || item === resource) return deny();
    }
    return {};
  }
  if (typeof audience !== 'string') return deny();
  if (audience !== resource) return {};

  if (
    token.kind !== 'AccessToken' ||
    !nonemptyString(token.gty) ||
    token.gty.split(/\s+/u).includes('client_credentials') ||
    !nonemptyString(token.accountId) ||
    !nonemptyString(token.clientId) ||
    typeof token.scope !== 'string' ||
    !token.scope.split(/\s+/u).includes('network:join')
  ) {
    return deny();
  }
  if (
    !isRecord(context) ||
    !isRecord(context.user) ||
    context.user.id !== token.accountId ||
    !isRecord(context.application) ||
    context.application.type !== 'Native'
  ) {
    return deny();
  }
  // Optional identity aliases must agree if present. Never take a replacement
  // account, product, client, or application type from request/custom data.
  if (
    ('sub' in token && token.sub !== token.accountId) ||
    ('sub' in context.user && context.user.sub !== token.accountId) ||
    ('client_id' in token && token.client_id !== token.clientId) ||
    ('azp' in token && token.azp !== token.clientId) ||
    ('id' in context.application && context.application.id !== token.clientId)
  ) {
    return deny();
  }

  let productId;
  let issuer;
  let epoch;
  let configVersion;
  let root;
  let seedHex;
  try {
    issuer = environmentVariables.ET_ISSUER;
    if (!nonemptyString(issuer)) throw new Error();
    const url = new URL(issuer);
    if (
      url.protocol !== 'https:' ||
      !url.hostname ||
      url.username ||
      url.password ||
      url.search ||
      url.hash ||
      !url.pathname.endsWith('/oidc') ||
      url.href !== issuer ||
      issuer !== url.origin + url.pathname
    ) {
      throw new Error();
    }

    epoch = environmentVariables.ET_CREDENTIAL_EPOCH;
    const maxU64 = '18446744073709551615';
    if (
      typeof epoch !== 'string' ||
      !/^(0|[1-9][0-9]*)$/u.test(epoch) ||
      epoch.length > maxU64.length ||
      (epoch.length === maxU64.length && epoch > maxU64)
    ) {
      throw new Error();
    }
    // Keep epoch as a string throughout, including its length-prefixed encoding.
    configVersion = environmentVariables.ET_CONFIG_VERSION;
    if (typeof configVersion !== 'string' || !/^[\x20-\x7e]{1,64}$/u.test(configVersion)) {
      throw new Error();
    }

    const productsJson = environmentVariables.ET_PRODUCTS_JSON;
    if (typeof productsJson !== 'string') throw new Error();
    const products = JSON.parse(productsJson);
    if (!Array.isArray(products) || products.length === 0) throw new Error();
    const productIds = new Set();
    const clientIds = new Set();
    for (const product of products) {
      if (
        !isRecord(product) ||
        !nonemptyString(product.productId) ||
        productIds.has(product.productId) ||
        !Array.isArray(product.nativeClientIds) ||
        product.nativeClientIds.length === 0
      ) {
        throw new Error();
      }
      productIds.add(product.productId);
      for (const clientId of product.nativeClientIds) {
        if (!nonemptyString(clientId) || clientIds.has(clientId)) throw new Error();
        clientIds.add(clientId);
        if (clientId === token.clientId) productId = product.productId;
      }
    }
    if (productId === undefined) throw new Error();

    const rootHex = environmentVariables.ET_ROOT_KEY_HEX;
    if (typeof rootHex !== 'string' || !/^[0-9a-fA-F]{64}$/u.test(rootHex)) {
      throw new Error();
    }
    root = new Uint8Array(32);
    for (let i = 0; i < root.length; i += 1) {
      root[i] = parseInt(rootHex.slice(i * 2, i * 2 + 2), 16);
    }

    const encoder = new TextEncoder();
    const fields = [
      '/seed/v1',
      issuer,
      token.accountId,
      productId,
      epoch,
    ].map((field) => {
      // TextEncoder replaces lone surrogates. Reject those malformed strings
      // to avoid distinct account/product strings sharing an encoded identity.
      for (let i = 0; i < field.length; i += 1) {
        const unit = field.charCodeAt(i);
        if (unit >= 0xd800 && unit <= 0xdbff) {
          const next = field.charCodeAt(i + 1);
          if (!(next >= 0xdc00 && next <= 0xdfff)) throw new Error();
          i += 1;
        } else if (unit >= 0xdc00 && unit <= 0xdfff) {
          throw new Error();
        }
      }
      const bytes = encoder.encode(field); // Original UTF-8; no normalization.
      if (bytes.length > 0xffffffff) throw new Error();
      return bytes;
    });
    const encoded = new Uint8Array(fields.reduce((length, field) => length + 4 + field.length, 0));
    const view = new DataView(encoded.buffer);
    let offset = 0;
    for (const field of fields) {
      view.setUint32(offset, field.length, false); // Four-byte unsigned big endian.
      offset += 4;
      encoded.set(field, offset);
      offset += field.length;
    }
    const key = await crypto.subtle.importKey(
      'raw', root, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    const seed = new Uint8Array(await crypto.subtle.sign('HMAC', key, encoded));
    seedHex = Array.from(seed, (byte) => byte.toString(16).padStart(2, '0')).join('');
    seed.fill(0);
  } catch {
    // Do not propagate parser or runtime error messages that may echo input.
    return deny();
  } finally {
    // Best effort only: JS strings and the runtime's CryptoKey cannot be wiped.
    if (root) root.fill(0);
  }

  // Logto keeps ownership of sub/iss/aud/exp and merges just these extra claims.
  return {
    client_id: token.clientId,
    'https://cyberbus.x.aixgg.com/easytier/credentials/v1': {
      version: 1,
      product_id: productId,
      credential_epoch: epoch,
      account_seed_secret_hex: seedHex,
      max_devices: 256,
      virtual_cidr: '10.144.0.0/20',
      control_port: 11000,
      config_version: configVersion,
    },
  };
};
