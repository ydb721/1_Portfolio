import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { b64 } from '../lib/webauthn.mjs';

// A deliberately small Redis REST double. The real Upstash service and device UI
// still need to be checked after deployment; this exercises the HTTP business flows.
const originalFetch = globalThis.fetch;
const strings = new Map(), hashes = new Map(), sets = new Map();
const get = key => strings.get(key) ?? null;
const hget = (key, field) => hashes.get(key)?.get(field) ?? null;
function command([op, ...a]) {
  if (op === 'GET') return get(a[0]);
  if (op === 'SET') { strings.set(a[0], a[1]); return 'OK'; }
  if (op === 'DEL') { const had = strings.delete(a[0]); return had ? 1 : 0; }
  if (op === 'GETDEL') { const value = get(a[0]); strings.delete(a[0]); return value; }
  if (op === 'SMEMBERS') return [...(sets.get(a[0]) || new Set())];
  if (op === 'HGETALL') return [...(hashes.get(a[0]) || new Map())].flat();
  if (op !== 'EVAL') throw Error(`missing test command ${op}`);
  const [script, amount, ...rest] = a;
  const keys = rest.slice(0, Number(amount)), args = rest.slice(Number(amount));
  if (script.includes('local account =')) {
    const [mode, accountId, handle, name, created, publicKey, counter, id, notes] = args;
    const existing = get(keys[0]);
    if (mode === 'new' ? existing || hashes.has(keys[1]) : existing !== accountId || hashes.has(keys[1])) return 0;
    if (mode === 'new') { strings.set(keys[0], accountId); strings.set(keys[3], handle); strings.set(keys[4], notes); }
    hashes.set(keys[1], new Map([['account', accountId], ['name', name], ['created', created], ['public', publicKey], ['counter', counter]]));
    if (!sets.has(keys[2])) sets.set(keys[2], new Set());
    sets.get(keys[2]).add(id); return 1;
  }
  if (script.includes('SCARD')) {
    if (hget(keys[0], 'account') !== args[0]) return -1;
    if ((sets.get(keys[1])?.size || 0) <= 1) return 0;
    hashes.delete(keys[0]); sets.get(keys[1]).delete(args[1]); return 1;
  }
  if (hget(keys[0], 'account') !== args[0] || hget(keys[0], 'counter') !== args[1] ||
      (Number(args[2]) !== 0 && Number(args[2]) <= Number(args[1]))) return 0;
  hashes.get(keys[0]).set('counter', args[2]); return 1;
}

function cbor(value) {
  const header = (major, n) => n < 24 ? Buffer.from([(major << 5) | n]) : n < 256 ? Buffer.from([(major << 5) | 24, n]) : Buffer.from([(major << 5) | 25, n >> 8, n & 255]);
  if (typeof value === 'number') return value >= 0 ? header(0, value) : header(1, -value - 1);
  if (typeof value === 'string') return Buffer.concat([header(3, Buffer.byteLength(value)), Buffer.from(value)]);
  if (Buffer.isBuffer(value)) return Buffer.concat([header(2, value.length), value]);
  if (value instanceof Map) return Buffer.concat([header(5, value.size), ...[...value].flatMap(([key, v]) => [cbor(key), cbor(v)])]);
  throw Error('invalid fixture');
}
const hash = input => createHash('sha256').update(input).digest();
const origin = 'http://localhost:3000';
function device() {
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = pair.publicKey.export({ format: 'jwk' }), id = randomBytes(24);
  return { id, pair, cose: cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')]])) };
}
const client = (type, challenge) => Buffer.from(JSON.stringify({ type, challenge, origin }));
function registration(options, key) {
  const size = Buffer.alloc(2); size.writeUInt16BE(key.id.length);
  const auth = Buffer.concat([hash('localhost'), Buffer.from([0x45, 0, 0, 0, 0]), Buffer.alloc(16), size, key.id, key.cose]);
  return { id: b64(key.id), response: { clientDataJSON: b64(client('webauthn.create', options.challenge)), attestationObject: b64(cbor(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', auth]]))) } };
}
function assertion(options, key, wrong = false) {
  key.counter = (key.counter || 0) + 1;
  const count = Buffer.alloc(4); count.writeUInt32BE(key.counter);
  const auth = Buffer.concat([hash('localhost'), Buffer.from([0x05]), count]);
  const data = client('webauthn.get', options.challenge);
  const signature = sign('sha256', Buffer.concat([auth, hash(data)]), key.pair.privateKey);
  if (wrong) signature[0] ^= 1;
  return { id: b64(key.id), response: { clientDataJSON: b64(data), authenticatorData: b64(auth), signature: b64(signature) } };
}

test('original public cards and passkey privacy / replay / two accounts', async () => {
  process.env.SITE_ORIGIN = origin;
  process.env.UPSTASH_REDIS_REST_URL = 'https://mock.redis.local';
  process.env.UPSTASH_REDIS_REST_TOKEN = 'only-in-test';
  globalThis.fetch = async (url, options) => {
    assert.equal(url, process.env.UPSTASH_REDIS_REST_URL);
    const result = command(JSON.parse(options.body));
    return new Response(JSON.stringify({ result }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  };
  const { default: handler } = await import('../api/gateway.js');
  let session = '';
  async function call(method, view, body, query = '', overrideCookie) {
    const req = { method, url: `/api/gateway?view=${view}${query}`, body,
      headers: { origin, 'content-type': 'application/json', cookie: overrideCookie ?? session } };
    const res = { headers: {}, status(code) { this.code = code; return this; }, json(value) { this.value = value; return this; }, setHeader(key, value) { this.headers[key] = value; } };
    await handler(req, res);
    if (res.headers['Set-Cookie']) session = res.headers['Set-Cookie'].split(';')[0];
    return { status: res.code, value: res.value };
  }
  async function enroll(handle, name, key) {
    const options = await call('POST', 'register-options', { handle, name });
    assert.equal(options.status, 200);
    const saved = await call('POST', 'register-verify', { ceremony: options.value.ceremony, credential: registration(options.value.options, key) });
    assert.equal(saved.status, 201);
    assert.deepEqual(Object.keys(saved.value.publicKey).sort(), ['crv', 'kty', 'x', 'y']);
    return options.value.options.challenge;
  }
  async function login(handle, key) {
    const options = await call('POST', 'login-options', { handle });
    assert.equal(options.status, 200);
    const result = await call('POST', 'login-verify', { ceremony: options.value.ceremony, credential: assertion(options.value.options, key) });
    assert.equal(result.status, 200);
    return options;
  }
  try {
    const html = await readFile(new URL('../index.html', import.meta.url), 'utf8');
    for (const copy of ['✨ My Strengths & Passions ✨', '성실함', '정리하기', '디테일', '카드를 클릭하면 상세 이야기를 확인']) assert.ok(html.includes(copy));
    assert.ok(!html.includes('가상 메모: 화면 흐름'));
    assert.equal((await call('GET', 'notes')).status, 401);
    const a1 = device(), a2 = device(), b1 = device();
    const regA = await call('POST', 'register-options', { handle: 'alpha', name: '첫 키' });
    const regB = await call('POST', 'register-options', { handle: 'alpha', name: '두 번째 시도' });
    assert.notEqual(regA.value.options.challenge, regB.value.options.challenge);
    assert.equal((await call('POST', 'login-options', { handle: 'alpha' })).status, 403); // canceled registration stored nothing
    assert.equal((await call('POST', 'register-verify', { ceremony: regB.value.ceremony, credential: registration(regB.value.options, a1) })).status, 201);
    const storedPublicKeyJWK = JSON.parse(hashes.get(`p8:key:${b64(a1.id)}`).get('public'));
    assert.equal((await call('POST', 'register-verify', { ceremony: regB.value.ceremony, credential: registration(regB.value.options, a1) })).status, 403);
    const loginA = await login('alpha', a1);
    assert.equal((await call('POST', 'login-verify', { ceremony: loginA.value.ceremony, credential: assertion(loginA.value.options, a1) })).status, 403);
    assert.equal((await call('GET', 'notes')).value.notes.length, 3);
    await enroll('ignored', '예비 키', a2);
    assert.equal((await call('GET', 'me')).value.passkeys.length, 2);
    const q1 = await call('POST', 'login-options', { handle: 'alpha' });
    const q2 = await call('POST', 'login-options', { handle: 'alpha' });
    assert.notEqual(q1.value.options.challenge, q2.value.options.challenge);
    const wrong = await call('POST', 'login-options', { handle: 'alpha' });
    assert.equal((await call('POST', 'login-verify', { ceremony: wrong.value.ceremony, credential: assertion(wrong.value.options, a2, true) })).status, 403);
    assert.equal((await call('DELETE', 'passkey', null, `&id=${b64(a1.id)}`)).status, 200);
    assert.equal((await call('DELETE', 'passkey', null, `&id=${b64(a2.id)}`)).status, 409);
    const oldSession = session;
    await call('POST', 'logout', {});
    assert.equal((await call('GET', 'notes', null, '', oldSession)).status, 401);
    const deleted = await call('POST', 'login-options', { handle: 'alpha' });
    assert.equal((await call('POST', 'login-verify', { ceremony: deleted.value.ceremony, credential: assertion(deleted.value.options, a1) })).status, 403);
    await login('alpha', a2);
    await call('POST', 'logout', {});
    await enroll('beta', '다른 계정 키', b1);
    await login('beta', b1);
    const alphaWithBeta = await call('POST', 'login-options', { handle: 'alpha' });
    assert.equal((await call('POST', 'login-verify', { ceremony: alphaWithBeta.value.ceremony, credential: assertion(alphaWithBeta.value.options, b1) })).status, 403);
    const betaBefore = (await call('GET', 'notes')).value.notes.length;
    assert.equal((await call('GET', 'notes', null, '&account=alpha')).status, 403);
    assert.equal((await call('GET', 'notes')).value.notes.length, betaBefore);
    assert.equal((await call('GET', 'notes', null, '&owner=alpha')).value.handle, 'beta');
    await call('POST', 'logout', {});
    await login('alpha', a2);
    const betaWithAlpha = await call('POST', 'login-options', { handle: 'beta' });
    assert.equal((await call('POST', 'login-verify', { ceremony: betaWithAlpha.value.ceremony, credential: assertion(betaWithAlpha.value.options, a2) })).status, 403);
    const alphaBefore = (await call('GET', 'notes')).value.notes.length;
    assert.equal((await call('GET', 'notes', null, '&account=beta')).status, 403);
    assert.equal((await call('GET', 'notes')).value.notes.length, alphaBefore);
    assert.equal((await call('GET', 'notes', null, '&owner=beta')).value.handle, 'alpha');
    await writeFile(new URL('./evidence.json', import.meta.url), JSON.stringify({
      kind: '합성 키 HTTP 테스트. 실제 기기 등록 증거 아님.',
      registrationChallenges: [regA.value.options.challenge.slice(0, 12) + '…', regB.value.options.challenge.slice(0, 12) + '…'],
      loginChallenges: [q1.value.options.challenge.slice(0, 12) + '…', q2.value.options.challenge.slice(0, 12) + '…'],
      storedPublicKeyJWK,
      requests: {
        anonymousNotes: 401, authenticatedNotes: 200, otherAccountBothDirections: 403,
        otherCredentialBothDirections: 403, reusedQuestion: 403, failedSignature: 403,
        deletedCredential: 403, remainingCredential: 200, lastCredentialDelete: 409,
        oldSessionAfterLogout: 401, recordsBeforeAfterCrossRequests: { alpha: [alphaBefore, alphaBefore], beta: [betaBefore, betaBefore] },
        ignoredOwnerQueryResponse: 'current session account',
      },
    }, null, 2) + '\n');
  } finally { globalThis.fetch = originalFetch; }
});
