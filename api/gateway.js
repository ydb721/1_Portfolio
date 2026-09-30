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
const examples = (handle = '') => handle === 'sample_2' ? [
  { title: '프로젝트', body: '가상의 일정 관리 화면을 설계합니다. 사용자가 오늘 할 일을 먼저 확인하도록 목록을 날짜순으로 정리하고, 완료한 항목은 별도 영역으로 이동합니다. 작은 화면에서도 추가·수정 버튼을 쉽게 찾을 수 있는지 점검합니다.' },
  { title: '관심 직무', body: '데이터 엔지니어 직무: SQL로 수집 데이터를 정리하고 품질을 검사한 경험을 중심으로 공고를 비교합니다. 서비스 운영 직무: 장애 원인을 기록하고 재발 방지 절차를 설명할 수 있는 사례를 준비합니다.' },
  { title: '리뷰', body: '가상의 일정 관리 화면에서 완료 표시가 눈에 잘 띄지 않았습니다. 다음 수정에서는 상태 색상과 텍스트를 함께 표시하고, 키보드만으로 항목을 추가하고 완료할 수 있는지도 확인합니다.' },
] : [
  { title: '프로젝트', body: "포트폴리오의 공개 카드는 로그인 없이 볼 수 있도록 유지함.\n비공개 영역은 패스키 인증 뒤에만 열리며, 로그아웃하거나 새로고침한 상태에서도 다른 계정의 메모가 보이지 않는지 확인.\n제출 전에는 휴대전화와 집 PC에서 각각 등록·로그인·로그아웃 흐름을 다시 점검함." },
  { title: '관심 직무', body: "보안: VMware 가상환경에서 모의해킹과 웹 취약점 진단·방어를 실습함.\n풀스택 개발: Spring Boot와 MySQL, React·Vue를 활용한 팀 프로젝트에서 프론트엔드와 백엔드 개발을 경험함.\n관심 언어: Java와 C에 관심이 있으며, Java로 GUI 게임과 웹 프로젝트를 구현함.\n바이브 코딩: AI와 협업하는 개발 방식에 관심이 있으며, 계획·실행·회고를 관리하는 Plan Do See Diary, 날씨 API를 연동한 정보판, 이미지 편집과 PNG 내보내기를 지원하는 카드 제작 도구를 구현함." },
  { title: '리뷰', body: "학원 PC에서는 블루투스와 Windows Hello PIN을 사용할 수 없어 패스키 테스트를 끝내지 못하여 노트북을 가져와 테스트를 마무리함.\n휴대전화에서는 계정 등록과 비공개 카드 표시를 확인함.\n집 PC에서 로그인을 재검증하고, 결과를 기기별로 구분해 과제 보고서에 기록할 예정임." },
];
// Replace only the sample notes created by earlier versions; preserve any other notes.
const formalExamples = (notes, handle) => {
  const updated = examples(handle);
  const defaultNotes = examples();
  const previous = [
    ["포트폴리오의 공개 카드는 로그인 없이 볼 수 있도록 유지했습니다. 비공개 영역은 패스키 인증 뒤에만 열리며, 로그아웃하거나 새로고침한 상태에서도 다른 계정의 메모가 보이지 않는지 확인할 계획입니다. 제출 전에는 휴대전화와 집 PC에서 각각 등록·로그인·로그아웃 흐름을 다시 점검하겠습니다.", "포트폴리오의 공개 카드는 로그인 없이 볼 수 있도록 유지함.\n비공개 영역은 패스키 인증 뒤에만 열리며, 로그아웃하거나 새로고침한 상태에서도 다른 계정의 메모가 보이지 않는지 확인할 계획임.\n제출 전에는 휴대전화와 집 PC에서 각각 등록·로그인·로그아웃 흐름을 다시 점검할 예정임.", `${handle}의 가상 메모: 화면 흐름을 세 단계로 줄이는 연습.`, `${handle}의 가상 메모: 화면 흐름을 세 단계로 줄이는 연습입니다.`],
    ["Java 백엔드 직무: 서버 API와 데이터베이스 설계 경험을 중심으로 공고를 비교합니다. 웹 보안 직무: 인증 흐름과 접근 제어 구현을 설명할 수 있는 사례를 보강합니다. 지원 순서는 필수 기술과 제 프로젝트의 증빙이 얼마나 맞는지 확인한 뒤 정할 예정입니다.", "Java 백엔드 직무: 서버 API와 데이터베이스 설계 경험을 중심으로 공고를 비교함.\n웹 보안 직무: 인증 흐름과 접근 제어 구현을 설명할 수 있는 사례를 보강함.\n지원 순서는 필수 기술과 제 프로젝트의 증빙이 얼마나 맞는지 확인한 뒤 정할 예정임.", "보안: 모의해킹, 취약점 진단·분석\n풀스택 개발: 프론트엔드, 백엔드\n관심 언어: Java, C", "보안: VMware 가상환경에서 모의해킹과 웹 취약점 진단·방어를 실습함.\n풀스택 개발: Spring Boot와 MySQL, React·Vue를 활용한 팀 프로젝트에서 프론트엔드와 백엔드 개발을 경험함.\n관심 언어: Java와 C에 관심이 있으며, Java로 GUI 게임과 웹 프로젝트를 구현함.\n바이브 코딩: AI와 협업하는 개발 방식에 관심이 있으며, 소개 페이지·러너 게임·패스키 인증 프로젝트를 제작하고 기능과 UI를 개선함.", `${handle}의 가상 목록: 예시 팀 A, 예시 팀 B, 예시 팀 C를 비교.`, `${handle}의 가상 목록: 예시 팀 A, 예시 팀 B, 예시 팀 C를 비교합니다.`],
    ["학원 PC에서는 블루투스와 Windows Hello PIN을 사용할 수 없어 패스키 테스트를 끝내지 못했습니다. 휴대전화에서는 계정 등록과 비공개 카드 표시를 확인했습니다. 집 PC에서 로그인을 재검증하고, 결과를 기기별로 구분해 과제 보고서에 기록하겠습니다.", "학원 PC에서는 블루투스와 Windows Hello PIN을 사용할 수 없어 패스키 테스트를 끝내지 못함.\n휴대전화에서는 계정 등록과 비공개 카드 표시를 확인함.\n집 PC에서 로그인을 재검증하고, 결과를 기기별로 구분해 과제 보고서에 기록할 예정임.", `${handle}의 가상 회고: 근거를 먼저 적고 다음 행동을 정하기.`, `${handle}의 가상 회고: 근거를 먼저 적고 다음 행동을 정합니다.`],
  ];
  return notes.map(note => {
    const title = ({ '프로젝트 메모': '프로젝트', '지원 후보': '관심 직무', '회고': '리뷰' })[note.title] || note.title;
    const index = updated.findIndex(item => item.title === title);
    return index >= 0 && (previous[index].includes(note.body) || note.body === defaultNotes[index].body)
      ? { ...note, title, body: updated[index].body } : { ...note, title };
  });
};

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  try {
    const origin = process.env.SITE_ORIGIN;
    if (!origin || new URL(origin).origin !== origin || (new URL(origin).protocol !== 'https:' && origin !== 'http://localhost:3000')) {
      return respond(res, 503, { error: '인증 환경이 아직 준비되지 않았습니다.' });
    }
    const rpId = new URL(origin).hostname;
    const view = new URL(req.url, origin).searchParams.get('view');
    if (!view) return respond(res, 404, { error: '없는 요청입니다.' });
    if (req.method !== 'GET' && req.headers.origin !== origin) return respond(res, 403, { error: '다른 출처의 요청입니다.' });
    const me = await currentUser(req);

    if (req.method === 'GET' && view === 'me') {
      return respond(res, 200, me ? { handle: me.handle, passkeys: (await getPasskeys(me.id)).map(({ id, name, created }) => ({ id, name, created })) } : { handle: null });
    }
    if (req.method === 'GET' && view === 'notes') {
      if (!me) return respond(res, 401, { error: '패스키로 로그인한 뒤 볼 수 있습니다.' });
      const requested = new URL(req.url, origin).searchParams.get('account');
      if (requested && requested !== me.handle) return respond(res, 403, { error: '다른 계정의 자료는 볼 수 없습니다.' });
      const notes = JSON.parse(await redis('GET', k.notes(me.id)) || '[]');
      const updated = formalExamples(notes, me.handle);
      if (updated.some((note, index) => note.body !== notes[index].body || note.title !== notes[index].title)) {
        await redis('SET', k.notes(me.id), JSON.stringify(updated));
      }
      return respond(res, 200, { handle: me.handle, notes: updated });
    }
    if (req.method === 'POST' && view === 'register-options') {
      const body = await bodyOf(req), handle = me?.handle ?? body.handle;
      if (!goodHandle(handle) || !goodName(body.name)) return respond(res, 400, { error: '계정명이나 패스키 이름을 확인해 주십시오.' });
      const accountId = await redis('GET', k.account(handle));
      if ((!me && accountId) || (me && accountId !== me.id)) return respond(res, 403, { error: '이미 등록된 계정입니다.' });
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
      if (!raw) return respond(res, 403, { error: '등록 질문이 이미 사용됐거나 만료됐습니다.' });
      const pending = JSON.parse(raw);
      if (pending.type !== 'registration' || (pending.mode === 'new' && me) ||
          (pending.mode === 'existing' && me?.id !== pending.accountId)) return respond(res, 403, { error: '등록 권한이 없습니다.' });
      let credential;
      try { credential = verifyRegistration(body.credential, pending.challenge, origin, rpId); }
      catch { return respond(res, 403, { error: '패스키 등록 응답이 올바르지 않습니다.' }); }
      const result = await savePasskey({ mode: pending.mode, accountId: pending.accountId,
        handle: pending.handle, credential, name: pending.name, notes: examples(pending.handle) });
      if (Number(result) !== 1) return respond(res, 409, { error: '이미 등록된 계정이나 패스키입니다.' });
      return respond(res, 201, { registered: true, name: pending.name, publicKey: credential.publicKey });
    }
    if (req.method === 'POST' && view === 'login-options') {
      const body = await bodyOf(req);
      if (!goodHandle(body.handle)) return respond(res, 400, { error: '계정명을 확인해 주십시오.' });
      const id = await redis('GET', k.account(body.handle));
      if (!id) return respond(res, 403, { error: '등록된 패스키가 없습니다.' });
      const keys = await getPasskeys(id);
      if (!keys.length) return respond(res, 403, { error: '남은 패스키가 없습니다. 복구 절차가 필요합니다.' });
      const challenge = nonce(), ceremony = randomUUID();
      await redis('SET', k.challenge(ceremony), JSON.stringify({ type: 'login', accountId: id, handle: body.handle, challenge }), 'EX', 120);
      return respond(res, 200, { ceremony, options: { challenge, rpId,
        allowCredentials: keys.map(key => ({ type: 'public-key', id: key.id })),
        userVerification: 'required', timeout: 120000 } });
    }
    if (req.method === 'POST' && view === 'login-verify') {
      const body = await bodyOf(req);
      const raw = typeof body.ceremony === 'string' ? await redis('GETDEL', k.challenge(body.ceremony)) : null;
      if (!raw) return respond(res, 403, { error: '로그인 질문이 이미 사용됐거나 만료됐습니다.' });
      const pending = JSON.parse(raw);
      if (pending.type !== 'login') return respond(res, 403, { error: '올바르지 않은 로그인 질문입니다.' });
      const key = typeof body.credential?.id === 'string' ? await getPasskey(body.credential.id) : null;
      if (!key || key.account !== pending.accountId) return respond(res, 403, { error: '이 계정의 패스키가 아닙니다.' });
      let counter;
      try { counter = verifyAuthentication(body.credential, { id: body.credential.id, publicKey: JSON.parse(key.public), counter: Number(key.counter) }, pending.challenge, origin, rpId); }
      catch { return respond(res, 403, { error: '패스키 서명 검증에 실패했습니다.' }); }
      if (Number(await saveCounter(body.credential.id, pending.accountId, key.counter, counter)) !== 1) {
        return respond(res, 403, { error: '이미 변경된 패스키입니다.' });
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
      if (!me) return respond(res, 401, { error: '로그인이 필요합니다.' });
      const id = new URL(req.url, origin).searchParams.get('id');
      if (!id || !/^[A-Za-z0-9_-]{8,512}$/.test(id)) return respond(res, 400, { error: '패스키 ID를 확인해 주십시오.' });
      const result = Number(await deletePasskey(me.id, id));
      if (result < 0) return respond(res, 403, { error: '이 계정의 패스키가 아닙니다.' });
      if (result === 0) return respond(res, 409, { error: '마지막 패스키는 삭제할 수 없습니다.' });
      return respond(res, 200, { deleted: true });
    }
    return respond(res, 404, { error: '없는 요청입니다.' });
  } catch (error) {
    console.error('passkey gateway error', error?.message);
    return respond(res, 503, { error: '인증 저장소를 사용할 수 없습니다. 잠시 뒤 다시 시도해 주십시오.' });
  }
}
