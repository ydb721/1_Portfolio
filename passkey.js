const $ = selector => document.querySelector(selector);
const bytes = value => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4)), c => c.charCodeAt(0));
const encoded = value => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const status = message => {
  const dialog = $('#passkey-dialog');
  if (!message) { if (dialog.open) dialog.close(); return; }
  $('#passkey-dialog-message').textContent = message;
  if (!dialog.open) dialog.showModal();
};
async function api(path, options = {}) {
  const res = await fetch(path, { credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, ...options });
  const data = await res.json();
  if (!res.ok) throw Error(data.error || '요청에 실패했습니다.');
  return data;
}
const post = (path, data) => api(path, { method: 'POST', body: JSON.stringify(data) });
const put = (path, data) => api(path, { method: 'PUT', body: JSON.stringify(data) });
function setPasskeyList(open) {
  if (open) setAddForm(false);
  $('#passkey-list-panel').hidden = !open;
  $('#passkey-show-list').setAttribute('aria-expanded', String(open));
}
function setAddForm(open) {
  if (open) setPasskeyList(false);
  $('#passkey-add').hidden = !open;
  $('#passkey-show-add').setAttribute('aria-expanded', String(open));
  if (open) $('#passkey-add [name="name"]').focus();
}
function creationOptions(options) {
  return { ...options, challenge: bytes(options.challenge), user: { ...options.user, id: bytes(options.user.id) },
    excludeCredentials: options.excludeCredentials.map(item => ({ ...item, id: bytes(item.id) })) };
}
function requestOptions(options, usePhone = false) {
  return { ...options, hints: usePhone ? ['hybrid'] : ['client-device'], challenge: bytes(options.challenge),
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
  status(handle ? '등록했습니다. 이제 새 패스키로 로그인해 주십시오.' : '패스키를 추가했습니다. 등록한 패스키 목록에서 확인할 수 있습니다.');
  if (handle) { $('#passkey-login [name="handle"]').value = handle;  }
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
  $('#passkey-locked').hidden = Boolean(me.handle);
  $('#passkey-unlocked').hidden = !me.handle;
  if (!me.handle) { setPasskeyList(false); $('#passkey-notes').replaceChildren(); $('#passkey-list').replaceChildren(); setAddForm(false); return; }
  $('#passkey-account').textContent = `계정: ${me.handle}`;
  const notes = await api('/api/gateway?view=notes');
  $('#passkey-notes').replaceChildren(...notes.notes.map((note, index) => {
    const card = document.createElement('article'), header = document.createElement('div'), h = document.createElement('h3'), title = document.createElement('span'), edit = document.createElement('button'), body = document.createElement('div'), p = document.createElement('p');
    header.className = 'note-header'; body.className = 'note-body';
    title.textContent = note.title; p.textContent = note.body;
    edit.type = 'button'; edit.className = 'note-edit secondary'; edit.textContent = '수정';
    edit.setAttribute('aria-label', `${note.title} 수정`);
    edit.addEventListener('click', () => editNote(card, index, notes.notes));
    h.append(title); header.append(h, edit); body.append(p); card.append(header, body); return card;
  }));
  $('#passkey-list').replaceChildren(...me.passkeys.map(key => {
    const li = document.createElement('li'), label = document.createElement('span'), button = document.createElement('button');
    label.textContent = `${key.name} · ${new Date(key.created).toLocaleDateString('ko-KR')}`;
    button.textContent = '삭제'; button.className = 'secondary';
    button.addEventListener('click', async () => {
      if (!confirm(`${key.name} 패스키를 계정에서 삭제하시겠습니까?`)) return;
      try { await api(`/api/gateway?view=passkey&id=${encodeURIComponent(key.id)}`, { method: 'DELETE' }); await refresh(); status('패스키를 삭제했습니다.'); }
      catch (error) { status(error.message); }
    });
    li.append(label, button); return li;
  }));
}
function editNote(card, index, notes) {
  const note = notes[index], form = document.createElement('form'), title = document.createElement('input'), body = document.createElement('textarea'), actions = document.createElement('div'), save = document.createElement('button'), cancel = document.createElement('button');
  form.className = 'note-edit-form';
  title.name = 'title'; title.value = note.title; title.maxLength = 30; title.required = true; title.setAttribute('aria-label', '카드 제목');
  body.name = 'body'; body.value = note.body; body.maxLength = 1500; body.required = true; body.rows = 9; body.setAttribute('aria-label', '카드 내용');
  actions.className = 'note-edit-actions'; save.type = 'submit'; save.textContent = '저장'; cancel.type = 'button'; cancel.className = 'secondary'; cancel.textContent = '취소';
  cancel.addEventListener('click', () => refresh().catch(error => status(error.message)));
  form.addEventListener('submit', async event => {
    event.preventDefault(); save.disabled = true;
    try {
      const updated = notes.map((item, position) => position === index ? { title: title.value, body: body.value } : item);
      await put('/api/gateway?view=notes', { notes: updated });
      await refresh(); status('비공개 카드를 저장했습니다.');
    } catch (error) { status(error.message); save.disabled = false; }
  });
  actions.append(save, cancel); form.append(title, body, actions); card.replaceChildren(form); title.focus();
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
$('#passkey-login').addEventListener('submit', event => action(event, form => login(form.get('handle'), true)));
$('#passkey-register').addEventListener('submit', event => action(event, form => register(form.get('handle'), form.get('name'))));
$('#passkey-show-list').addEventListener('click', () => setPasskeyList($('#passkey-list-panel').hidden));
document.addEventListener('click', event => { if (!$('#passkey-list-panel').hidden && !event.target.closest('.passkey-list-anchor')) setPasskeyList(false); });
document.addEventListener('keydown', event => { if (event.key === 'Escape' && !$('#passkey-list-panel').hidden) { setPasskeyList(false); $('#passkey-show-list').focus(); } });
$('#passkey-show-add').addEventListener('click', () => setAddForm($('#passkey-add').hidden));
document.addEventListener('click', event => {
  if (!$('#passkey-add').hidden && !event.target.closest('.passkey-add-anchor')) setAddForm(false);
});
document.addEventListener('keydown', event => {
  if (event.key === 'Escape' && !$('#passkey-add').hidden) {
    setAddForm(false);
    $('#passkey-show-add').focus();
  }
});
$('#passkey-add').addEventListener('submit', event => action(event, async form => {
  if (await register('', form.get('name'))) { setAddForm(false); await refresh(); }
}));
$('#passkey-logout').addEventListener('click', async () => {
  try { await post('/api/gateway?view=logout', {}); await refresh(); status(''); }
  catch (error) { status(error.message); }
});
document.querySelectorAll('[data-passkey-notice]').forEach(button => {
  button.addEventListener('click', () => status(button.dataset.passkeyNotice));
});
refresh().catch(error => status(error.message));
