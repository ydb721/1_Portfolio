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
function creationOptions(options) {
  return { ...options, challenge: bytes(options.challenge), user: { ...options.user, id: bytes(options.user.id) },
    excludeCredentials: options.excludeCredentials.map(item => ({ ...item, id: bytes(item.id) })) };
}
function requestOptions(options) {
  return { ...options, challenge: bytes(options.challenge), allowCredentials: options.allowCredentials.map(item => ({ ...item, id: bytes(item.id) })) };
}
async function register(handle, name) {
  const { ceremony, options } = await post('/api/gateway?view=register-options', { handle, name });
  let response;
  try { response = await navigator.credentials.create({ publicKey: creationOptions(options) }); }
  catch (error) { status('등록을 취소했습니다. 서버에 새 패스키는 저장되지 않았습니다.'); return; }
  const credential = { id: encoded(response.rawId), response: {
    clientDataJSON: encoded(response.response.clientDataJSON), attestationObject: encoded(response.response.attestationObject) } };
  await post('/api/gateway?view=register-verify', { ceremony, credential });
  status('등록했습니다. 이제 패스키로 로그인해 주십시오. 패스키 목록은 로그인한 뒤 볼 수 있습니다.');
  if (handle) $('#passkey-login [name="handle"]').value = handle;
}
async function login(handle) {
  const { ceremony, options } = await post('/api/gateway?view=login-options', { handle });
  let response;
  try { response = await navigator.credentials.get({ publicKey: requestOptions(options) }); }
  catch { status('패스키 로그인을 취소했습니다. 다시 시도할 수 있습니다.'); return; }
  const credential = { id: encoded(response.rawId), response: { clientDataJSON: encoded(response.response.clientDataJSON),
    authenticatorData: encoded(response.response.authenticatorData), signature: encoded(response.response.signature) } };
  await post('/api/gateway?view=login-verify', { ceremony, credential });
  status('패스키 서명을 확인했습니다.');
  await refresh();
}
async function refresh() {
  const me = await api('/api/gateway?view=me');
  $('#passkey-locked').hidden = Boolean(me.handle);
  $('#passkey-unlocked').hidden = !me.handle;
  if (!me.handle) { $('#passkey-notes').replaceChildren(); $('#passkey-list').replaceChildren(); return; }
  $('#passkey-account').textContent = `계정: ${me.handle}`;
  const notes = await api('/api/gateway?view=notes');
  $('#passkey-notes').replaceChildren(...notes.notes.map(note => {
    const card = document.createElement('article'), h = document.createElement('h3'), p = document.createElement('p');
    h.textContent = note.title; p.textContent = note.body; card.append(h, p); return card;
  }));
  $('#passkey-list').replaceChildren(...me.passkeys.map(key => {
    const li = document.createElement('li'), label = document.createElement('span'), button = document.createElement('button');
    label.textContent = `${key.name} · ${new Date(key.created).toLocaleDateString('ko-KR')}`;
    button.textContent = '삭제'; button.className = 'secondary';
    button.addEventListener('click', async () => {
      if (!confirm(`${key.name} 패스키를 계정에서 삭제하시겠습니까?`)) return;
      try { await api(`/api/gateway?view=passkey&id=${encodeURIComponent(key.id)}`, { method: 'DELETE' }); status('패스키를 삭제했습니다.'); await refresh(); }
      catch (error) { status(error.message); }
    });
    li.append(label, button); return li;
  }));
}
async function action(event, callback) {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button[type="submit"]');
  button.disabled = true;
  try {
    if (!window.PublicKeyCredential || !window.isSecureContext) throw Error('HTTPS와 패스키 지원 브라우저가 필요합니다.');
    await callback(new FormData(event.currentTarget));
  } catch (error) { status(error.message); }
  finally { button.disabled = false; }
}
$('#passkey-login').addEventListener('submit', event => action(event, form => login(form.get('handle'))));
$('#passkey-register').addEventListener('submit', event => action(event, form => register(form.get('handle'), form.get('name'))));
$('#passkey-add').addEventListener('submit', event => action(event, async form => { await register('', form.get('name')); await refresh(); }));
$('#passkey-logout').addEventListener('click', async () => {
  try { await post('/api/gateway?view=logout', {}); await refresh(); status('로그아웃했습니다. 비공개 내용은 화면에서 지웠습니다.'); }
  catch (error) { status(error.message); }
});
refresh().catch(error => status(error.message));
