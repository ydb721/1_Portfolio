import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { b64, verifyRegistration, verifyAuthentication } from '../lib/webauthn.mjs';
import { redis, k, getPasskey, getPasskeys, savePasskey, deletePasskey, saveCounter } from '../lib/redis.mjs';

const nonce = () => b64(randomBytes(32));
const digest = token => createHash('sha256').update(token).digest('hex');
const goodHandle = value => typeof value === 'string' && /^[a-z0-9_-]{3,24}$/.test(value);
const goodName = value => typeof value === 'string' && value.trim().length > 0 && value.length <= 40;
const respond = (res, code, value) => res.status(code).json(value);
const cookie = (token, secure) => `intro_session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800${secure ? '; Secure' : ''}`;
const currentCookie = req => /(?:^|;\s*)intro_session=([A-Za-z0-9_-]+)/.exec(req.headers.cookie || '')?.[1];
async function currentUser(req) {
  const token = currentCookie(req);
  if (!token) return null;
  const id = await redis('GET', k.session(digest(token)));
  if (!id) return null;
  const handle = await redis('GET', k.accountName(id));
  return handle ? { id, handle } : null;
}
async function bodyOf(req) {
  if (!String(req.headers['content-type'] || '').startsWith('application/json')) throw Error('JSON required');
  if (typeof req.body === 'object' && req.body !== null) return req.body;
  if (typeof req.body === 'string' && req.body.length < 50000) return JSON.parse(req.body);
  let value = '';
  for await (const piece of req) { value += piece; if (value.length > 50000) throw Error('body too large'); }
  return JSON.parse(value || '{}');
}
const examples = handle => [
  { title: '프로젝트 메모', body: `${handle}의 가상 메모: 화면 흐름을 세 단계로 줄이는 연습.` },
  { title: '지원 후보', body: `${handle}의 가상 목록: 예시 팀 A, 예시 팀 B, 예시 팀 C를 비교.` },
  { title: '회고', body: `${handle}의 가상 회고: 근거를 먼저 적고 다음 행동을 정하기.` },
];

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  try {
    const origin = process.env.SITE_ORIGIN;
    if (!origin || new URL(origin).origin !== origin || (new URL(origin).protocol !== 'https:' && origin !== 'http://localhost:3000')) {
      return respond(res, 503, { error: '인증 환경이 아직 준비되지 않았어.' });
    }
    const rpId = new URL(origin).hostname;
    const view = new URL(req.url, origin).searchParams.get('view');
    if (!view) return respond(res, 404, { error: '없는 요청이야.' });
    if (req.method !== 'GET' && req.headers.origin !== origin) return respond(res, 403, { error: '다른 출처의 요청이야.' });
    const me = await currentUser(req);

    if (req.method === 'GET' && view === 'me') {
      return respond(res, 200, me ? { handle: me.handle, passkeys: (await getPasskeys(me.id)).map(({ id, name, created }) => ({ id, name, created })) } : { handle: null });
    }
    if (req.method === 'GET' && view === 'notes') {
      if (!me) return respond(res, 401, { error: '패스키로 들어간 뒤 볼 수 있어.' });
      const requested = new URL(req.url, origin).searchParams.get('account');
      if (requested && requested !== me.handle) return respond(res, 403, { error: '다른 계정의 자료는 볼 수 없어.' });
      const notes = JSON.parse(await redis('GET', k.notes(me.id)) || '[]');
      return respond(res, 200, { handle: me.handle, notes });
    }
    if (req.method === 'POST' && view === 'register-options') {
      const body = await bodyOf(req), handle = me?.handle ?? body.handle;
      if (!goodHandle(handle) || !goodName(body.name)) return respond(res, 400, { error: '계정명이나 패스키 이름을 확인해 줘.' });
      const accountId = await redis('GET', k.account(handle));
      if ((!me && accountId) || (me && accountId !== me.id)) return respond(res, 403, { error: '이미 등록된 계정이야.' });
      const userId = accountId || randomUUID(), challenge = nonce(), ceremony = randomUUID();
      const pending = { type: 'registration', mode: accountId ? 'existing' : 'new', accountId: userId, handle, name: body.name.trim(), challenge };
      await redis('SET', k.challenge(ceremony), JSON.stringify(pending), 'EX', 120);
      return respond(res, 200, { ceremony, options: { challenge, rp: { id: rpId, name: '나만 보는 자리' },
        user: { id: b64(Buffer.from(userId)), name: handle, displayName: handle },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }], timeout: 120000,
        excludeCredentials: (accountId ? await getPasskeys(accountId) : []).map(item => ({ type: 'public-key', id: item.id })),
        attestation: 'none', authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' } } });
    }
    if (req.method === 'POST' && view === 'register-verify') {
      const body = await bodyOf(req);
      const raw = typeof body.ceremony === 'string' ? await redis('GETDEL', k.challenge(body.ceremony)) : null;
      if (!raw) return respond(res, 403, { error: '등록 질문이 이미 쓰였거나 만료됐어.' });
      const pending = JSON.parse(raw);
      if (pending.type !== 'registration' || (pending.mode === 'new' && me) ||
          (pending.mode === 'existing' && me?.id !== pending.accountId)) return respond(res, 403, { error: '등록 권한이 없어.' });
      let credential;
      try { credential = verifyRegistration(body.credential, pending.challenge, origin, rpId); }
      catch { return respond(res, 403, { error: '패스키 등록 응답이 틀렸어.' }); }
      const result = await savePasskey({ mode: pending.mode, accountId: pending.accountId,
        handle: pending.handle, credential, name: pending.name, notes: examples(pending.handle) });
      if (Number(result) !== 1) return respond(res, 409, { error: '이미 등록된 계정이나 패스키야.' });
      return respond(res, 201, { registered: true, name: pending.name, publicKey: credential.publicKey });
    }
    if (req.method === 'POST' && view === 'login-options') {
      const body = await bodyOf(req);
      if (!goodHandle(body.handle)) return respond(res, 400, { error: '계정명을 확인해 줘.' });
      const id = await redis('GET', k.account(body.handle));
      if (!id) return respond(res, 403, { error: '등록된 패스키가 없어.' });
      const keys = await getPasskeys(id);
      if (!keys.length) return respond(res, 403, { error: '남은 패스키가 없어. 복구 절차가 필요해.' });
      const challenge = nonce(), ceremony = randomUUID();
      await redis('SET', k.challenge(ceremony), JSON.stringify({ type: 'login', accountId: id, handle: body.handle, challenge }), 'EX', 120);
      return respond(res, 200, { ceremony, options: { challenge, rpId,
        allowCredentials: keys.map(key => ({ type: 'public-key', id: key.id })),
        userVerification: 'required', timeout: 120000 } });
    }
    if (req.method === 'POST' && view === 'login-verify') {
      const body = await bodyOf(req);
      const raw = typeof body.ceremony === 'string' ? await redis('GETDEL', k.challenge(body.ceremony)) : null;
      if (!raw) return respond(res, 403, { error: '로그인 질문이 이미 쓰였거나 만료됐어.' });
      const pending = JSON.parse(raw);
      if (pending.type !== 'login') return respond(res, 403, { error: '잘못된 로그인 질문이야.' });
      const key = typeof body.credential?.id === 'string' ? await getPasskey(body.credential.id) : null;
      if (!key || key.account !== pending.accountId) return respond(res, 403, { error: '이 계정의 패스키가 아니야.' });
      let counter;
      try { counter = verifyAuthentication(body.credential, { id: body.credential.id, publicKey: JSON.parse(key.public), counter: Number(key.counter) }, pending.challenge, origin, rpId); }
      catch { return respond(res, 403, { error: '패스키 서명 검증에 실패했어.' }); }
      if (Number(await saveCounter(body.credential.id, pending.accountId, key.counter, counter)) !== 1) {
        return respond(res, 403, { error: '이미 바뀐 패스키야.' });
      }
      const prior = currentCookie(req);
      if (prior) await redis('DEL', k.session(digest(prior)));
      const token = nonce();
      await redis('SET', k.session(digest(token)), pending.accountId, 'EX', 604800);
      res.setHeader('Set-Cookie', cookie(token, origin.startsWith('https:')));
      return respond(res, 200, { authenticated: true, handle: pending.handle });
    }
    if (req.method === 'POST' && view === 'logout') {
      const token = currentCookie(req);
      if (token) await redis('DEL', k.session(digest(token)));
      res.setHeader('Set-Cookie', cookie('', origin.startsWith('https:')).replace('Max-Age=604800', 'Max-Age=0'));
      return respond(res, 200, { loggedOut: true });
    }
    if (req.method === 'DELETE' && view === 'passkey') {
      if (!me) return respond(res, 401, { error: '로그인이 필요해.' });
      const id = new URL(req.url, origin).searchParams.get('id');
      if (!id || !/^[A-Za-z0-9_-]{8,512}$/.test(id)) return respond(res, 400, { error: '패스키 ID를 확인해 줘.' });
      const result = Number(await deletePasskey(me.id, id));
      if (result < 0) return respond(res, 403, { error: '내 패스키가 아니야.' });
      if (result === 0) return respond(res, 409, { error: '마지막 패스키는 지울 수 없어.' });
      return respond(res, 200, { deleted: true });
    }
    return respond(res, 404, { error: '없는 요청이야.' });
  } catch (error) {
    console.error('passkey gateway error', error?.message);
    return respond(res, 503, { error: '인증 저장소를 사용할 수 없어. 잠시 뒤 다시 해 줘.' });
  }
}
