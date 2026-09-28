const $ = selector => document.querySelector(selector);
const bytes = value => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4)), c => c.charCodeAt(0));
const encoded = value => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const status = message => { $('#passkey-status').textContent = message; };
async function api(path, options = {}) {
  const res = await fetch(path, { credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, ...options });
  const data = await res.json();
  if (!res.ok) throw Error(data.error || '요청에 실패했습니다.');
  return data;
}
const post = (path, data) => api(path, { method: 'POST', body: JSON.stringify(data) });
function showAuthView(view) {
  const isLogin = view === 'login';
  $('#passkey-login-panel').hidden = !isLogin;
  $('#passkey-register-panel').hidden = isLogin;
  $('#register-guidance').hidden = isLogin;
  $('#passkey-show-login').setAttribute('aria-pressed', String(isLogin));
  $('#passkey-show-register').setAttribute('aria-pressed', String(!isLogin));
}
function setPublicPreview(open) {
  document.body.classList.toggle('public-preview-open', open);
  const button = $('#passkey-public-preview');
  button.textContent = open ? '공개 카드 접기' : '로그인 없이 공개 카드 보기';
  button.setAttribute('aria-expanded', String(open));
}
function setPasskeyList(open) {
  $('#passkey-list-panel').hidden = !open;
  $('#passkey-show-list').setAttribute('aria-expanded', String(open));
  if (open) $('#passkey-list-status').textContent = '';
}
function setAddForm(open) {
  $('#passkey-add').hidden = !open;
  $('#passkey-show-add').setAttribute('aria-expanded', String(open));
  $('.private-space').classList.toggle('add-form-open', open);
  if (open) $('#passkey-add [name="name"]').focus();
}
function creationOptions(options) {
  return { ...options, challenge: bytes(options.challenge), user: { ...options.user, id: bytes(options.user.id) },
    excludeCredentials: options.excludeCredentials.map(item => ({ ...item, id: bytes(item.id) })) };
}
function requestOptions(options, usePhone = false) {
  return { ...options, ...(usePhone ? { hints: ['hybrid'] } : {}), challenge: bytes(options.challenge),
    allowCredentials: usePhone ? [] : options.allowCredentials.map(item => ({ ...item, id: bytes(item.id) })) };
}
async function register(handle, name) {
  const { ceremony, options } = await post('/api/gateway?view=register-options', { handle, name });
  let response;
  try { response = await navigator.credentials.create({ publicKey: creationOptions(options) }); }
  catch (error) { status('등록을 취소했습니다. 서버에 새 패스키는 저장되지 않았습니다.'); return false; }
  const credential = { id: encoded(response.rawId), response: {
    clientDataJSON: encoded(response.response.clientDataJSON), attestationObject: encoded(response.response.attestationObject) } };
  await post('/api/gateway?view=register-verify', { ceremony, credential });
  status('등록했습니다. 이제 패스키로 로그인해 주십시오. 패스키 목록은 로그인한 뒤 볼 수 있습니다.');
  if (handle) { $('#passkey-login [name="handle"]').value = handle; showAuthView('login'); }
  return true;
}
async function login(handle, usePhone = false) {
  const { ceremony, options } = await post('/api/gateway?view=login-options', { handle });
  let response;
  try { response = await navigator.credentials.get({ publicKey: requestOptions(options, usePhone) }); }
  catch (error) { status(usePhone ? `휴대전화 패스키 로그인을 완료하지 못했습니다. 브라우저 오류: ${error.name || '알 수 없음'}` : '패스키 로그인을 취소했습니다. 다시 시도할 수 있습니다.'); return; }
  const credential = { id: encoded(response.rawId), response: { clientDataJSON: encoded(response.response.clientDataJSON),
    authenticatorData: encoded(response.response.authenticatorData), signature: encoded(response.response.signature) } };
  await post('/api/gateway?view=login-verify', { ceremony, credential });
  await refresh();
  status('');
  $('.private-space').scrollIntoView({ behavior: 'smooth', block: 'start' });
}
async function refresh() {
  const me = await api('/api/gateway?view=me');
  document.body.classList.toggle('passkey-signed-in', Boolean(me.handle));
  $('.private-space').setAttribute('aria-labelledby', me.handle ? 'private-title-signed-in' : 'private-title');
  if (!me.handle) setPublicPreview(false);
  $('#passkey-locked').hidden = Boolean(me.handle);
  $('#passkey-unlocked').hidden = !me.handle;
  if (!me.handle) { setPasskeyList(false); $('#passkey-notes').replaceChildren(); $('#passkey-list').replaceChildren(); setAddForm(false); return; }
  $('#passkey-account').textContent = `계정: ${me.handle}`;
  const notes = await api('/api/gateway?view=notes');
  $('#passkey-notes').replaceChildren(...notes.notes.map(note => {
    const card = document.createElement('article'), header = document.createElement('div'), h = document.createElement('h3'), title = document.createElement('span'), body = document.createElement('div'), p = document.createElement('p');
    header.className = 'note-header'; body.className = 'note-body';
    title.textContent = note.title; p.textContent = note.body;
    h.append(title); header.append(h); body.append(p); card.append(header, body); return card;
  }));
  $('#passkey-list').replaceChildren(...me.passkeys.map(key => {
    const li = document.createElement('li'), label = document.createElement('span'), button = document.createElement('button');
    label.textContent = `${key.name} · ${new Date(key.created).toLocaleDateString('ko-KR')}`;
    button.textContent = '삭제'; button.className = 'secondary';
    button.addEventListener('click', async () => {
      if (!confirm(`${key.name} 패스키를 계정에서 삭제하시겠습니까?`)) return;
      try { await api(`/api/gateway?view=passkey&id=${encodeURIComponent(key.id)}`, { method: 'DELETE' }); await refresh(); $('#passkey-list-status').textContent = ''; }
      catch (error) { $('#passkey-list-status').textContent = error.message; }
    });
    li.append(label, button); return li;
  }));
}
async function action(event, callback) {
  event.preventDefault();
  const button = event.submitter ?? event.currentTarget.querySelector('button[type="submit"]');
  button.disabled = true;
  try {
    if (!window.PublicKeyCredential || !window.isSecureContext) throw Error('HTTPS와 패스키 지원 브라우저가 필요합니다.');
    await callback(new FormData(event.currentTarget));
  } catch (error) { status(error.message); }
  finally { button.disabled = false; }
}
$('#passkey-login').addEventListener('submit', event => {
  const usePhone = event.submitter?.value === 'phone';
  action(event, form => login(form.get('handle'), usePhone));
});
$('#passkey-register').addEventListener('submit', event => action(event, form => register(form.get('handle'), form.get('name'))));
$('#passkey-show-login').addEventListener('click', () => showAuthView('login'));
$('#passkey-show-register').addEventListener('click', () => showAuthView('register'));
$('#passkey-public-preview').addEventListener('click', () => {
  const open = !document.body.classList.contains('public-preview-open');
  setPublicPreview(open);
});
$('#passkey-show-list').addEventListener('click', () => setPasskeyList($('#passkey-list-panel').hidden));
document.addEventListener('click', event => { if (!$('#passkey-list-panel').hidden && !event.target.closest('.passkey-list-anchor')) setPasskeyList(false); });
document.addEventListener('keydown', event => { if (event.key === 'Escape' && !$('#passkey-list-panel').hidden) { setPasskeyList(false); $('#passkey-show-list').focus(); } });
$('#passkey-show-add').addEventListener('click', () => setAddForm($('#passkey-add').hidden));
$('#passkey-add').addEventListener('submit', event => action(event, async form => {
  if (await register('', form.get('name'))) { setAddForm(false); await refresh(); }
}));
$('#passkey-logout').addEventListener('click', async () => {
  try { await post('/api/gateway?view=logout', {}); await refresh(); status(''); }
  catch (error) { status(error.message); }
});
refresh().catch(error => status(error.message));
