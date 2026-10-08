import {copyUserLink} from './credential-link.mjs?v=20260928-modal1';

export function credentialsText(login, password, url) {
  if (!password) throw new Error('Сначала создайте новый пароль кнопкой «Сгенерировать и сменить пароль».');
  return `Логин: ${login}\nПароль: ${password}\nСсылка: ${url}`;
}

export function personalUrl(path, origin) {
  if (typeof path !== 'string' || !/^\/[a-f0-9-]{36}\.[A-Za-z0-9_-]{43}\/$/.test(path)) throw new Error('Некорректная персональная ссылка');
  return new URL(path, origin).href;
}

export async function accountRequest(path, payload) {
  const token = window.fortisSessionMarker?.() || '';
  const response = await fetch(`/api/account-cards${path}`, {
    method: payload ? 'POST' : 'GET', cache: 'no-store',
    headers: { ...(payload ? {'Content-Type':'application/json'} : {})},
    ...(payload ? {body:JSON.stringify(payload)} : {}),
  });
  if (response.status === 401) window.dispatchEvent(new CustomEvent('vpn:unauthorized', {detail:{token}}));
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : data?.error?.message || 'Не удалось загрузить карточку');
  return data;
}

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text) node.textContent = text;
  if (className) node.className = className;
  return node;
}
function button(text, action, className = 'btn ghost') {
  const node = element('button', text, className); node.type = 'button';
  node.addEventListener('click', action); return node;
}
function field(parent, title, value, secret = false) {
  const label = element('label', '', 'field');
  const input = element('input'); input.readOnly = true; input.value = value;
  input.type = secret ? 'password' : 'text'; input.autocomplete = 'off'; input.spellcheck = false;
  label.append(element('span', title), input); parent.append(label); return input;
}
function dialog(title, alert = false) {
  const node = element('dialog', '', 'workflow-dialog account-card');
  if (alert) node.setAttribute('role', 'alertdialog');
  node.setAttribute('aria-label', title);
  const header = element('div', '', 'workflow-dialog-head');
  const close = button('×', () => node.close()); close.setAttribute('aria-label', 'Закрыть карточку');
  header.append(element('h2', title), close);
  const body = element('div', '', 'workflow-dialog-body');
  node.append(header, body); document.body.append(node);
  node.addEventListener('close', () => { node.querySelectorAll('input').forEach(input => {input.value = '';}); node.remove(); });
  node.showModal(); return {node, body, close};
}

export async function openAccountCard(id, request = accountRequest) {
  const view = dialog('Карточка учётной записи');
  const status = element('p', 'Загрузка…', 'muted'); status.setAttribute('role','status');
  view.body.append(status);
  let data;
  try { data = await request(`/${encodeURIComponent(id)}`); } catch (error) { status.textContent = error.message; return; }
  if (!view.node.isConnected) return;
  status.textContent = '';
  const name = element('h3', data.fullName);
  const roles = {ADMIN:'Администратор', IT_LEAD:'Руководитель ИТ', IT_STAFF:'Сотрудник ИТ'};
  view.body.prepend(name, element('p', roles[data.role] || data.role, 'muted'));
  const fields = element('div', '', 'account-card-fields'); view.body.append(fields);
  field(fields, 'Логин', data.email);
  let url;
  try { url = personalUrl(data.path, location.origin); } catch (error) { status.textContent = error.message; return; }
  const link = field(fields, 'Персональная ссылка входа', url, true);
  const actions = element('div', '', 'toolbar'); fields.append(actions);
  actions.append(button('Показать ссылку', event => {
    link.type = link.type === 'password' ? 'text' : 'password';
    event.currentTarget.textContent = link.type === 'password' ? 'Показать ссылку' : 'Скрыть ссылку';
  }), button('Скопировать ссылку', async () => {
    try { await copyUserLink(link.value); status.textContent = 'Ссылка скопирована'; }
    catch (error) { status.textContent = error.message; }
  }));
  let passwordField = null;
  const copyAll = button('Скопировать логин, пароль и ссылку', async () => {
    try { await copyUserLink(credentialsText(data.email, passwordField?.value, link.value)); status.textContent = 'Логин, пароль и ссылка скопированы'; }
    catch (error) { status.textContent = error.message; }
  }, 'btn');
  copyAll.disabled = true;
  const copyHint = element('p', 'Генератор создаст случайный пароль из 24 символов. После подтверждения он заменит текущий пароль, и вы сможете скопировать все данные входа. Текущий пароль восстановить нельзя.', 'muted');
  copyHint.id = 'account-copy-hint'; copyAll.setAttribute('aria-describedby', copyHint.id);
  view.body.append(copyAll, copyHint);
  if (!data.active) view.body.append(element('p', 'Учётная запись заблокирована: вход и сброс пароля недоступны.', 'muted'));
  const resetButton = button('Сгенерировать и сменить пароль', () => confirmReset(), 'btn');
  resetButton.disabled = !data.active; view.body.append(resetButton);

  function confirmReset() {
    const confirm = dialog('Сгенерировать и сменить пароль?', true);
    const warning = element('p', `Для ${data.email} сервер сгенерирует случайный пароль из 24 символов и новую ссылку. Старые пароль, ссылка и сеансы перестанут работать. TOTP не изменится. Пароль изменится только после подтверждения.`);
    warning.id = 'account-reset-warning'; confirm.node.setAttribute('aria-describedby', warning.id);
    confirm.body.append(warning);
    const label = element('label', '', 'field'); const login = element('input');
    login.autocomplete = 'off'; label.append(element('span', 'Для подтверждения введите логин'), login); confirm.body.append(label);
    const error = element('p'); error.setAttribute('role','alert'); confirm.body.append(error);
    const toolbar = element('div', '', 'toolbar');
    const cancel = button('Отмена', () => confirm.node.close());
    const submit = button('Подтвердить генерацию и смену', async () => {
      submit.disabled = true; cancel.disabled = true; confirm.close.disabled = true;
      let pending = true;
      const prevent = event => { if (pending) event.preventDefault(); };
      confirm.node.addEventListener('cancel', prevent);
      error.textContent = '';
      try {
        const updated = await request(`/${encodeURIComponent(id)}/reset-password`, {confirmLogin:login.value, expectedPath:data.path});
        data = updated; url = personalUrl(data.path, location.origin); link.value = url;
        if (data.self) window.fortisClearSessionHint?.();
        pending = false; confirm.node.close(); resetButton.remove();
        const result = element('section'); result.setAttribute('aria-label', 'Новые данные входа');
        result.append(element('h3', 'Пароль сгенерирован и изменён'), element('p', 'Сохраните данные сейчас. После закрытия карточки пароль больше не отображается.', 'muted'));
        const password = field(result, 'Новый пароль', data.password, true);
        passwordField = password; copyAll.disabled = false;
        copyHint.textContent = 'Кнопка копирует логин, новый пароль и актуальную ссылку одним текстом. После закрытия карточки пароль больше недоступен.';
        data.password = ''; // Keep the secret only in the visible, removable field.
        const tools = element('div', '', 'toolbar');
        tools.append(button('Показать пароль', event => {
          password.type = password.type === 'password' ? 'text' : 'password';
          event.currentTarget.textContent = password.type === 'password' ? 'Показать пароль' : 'Скрыть пароль';
        }));
        result.append(tools); view.body.append(result);
        status.textContent = 'Старые пароль, ссылка и сеансы отозваны.';
        if (data.self) {
          view.body.append(button('Войти по новой ссылке', () => location.assign(url), 'btn'));
          view.node.addEventListener('close', () => location.assign(url), {once:true});
        }
        password.focus();
      } catch (err) { error.textContent = `${err.message}. При потере ответа не повторяйте запрос автоматически: откройте карточку заново.`; }
      finally { pending = false; submit.disabled = login.value !== data.email; cancel.disabled = false; confirm.close.disabled = false; }
    }, 'btn danger');
    submit.disabled = true;
    login.addEventListener('input', () => { submit.disabled = login.value !== data.email; });
    toolbar.append(cancel, submit); confirm.body.append(toolbar); login.focus();
  }
}

export function enhanceAccountRows(root, accounts, open = openAccountCard) {
  const byLogin = new Map(accounts.map(account => [account.email, account]));
  for (const row of root.querySelectorAll('tbody tr')) {
    const cells = row.querySelectorAll('td');
    const account = byLogin.get(cells[1]?.textContent.trim());
    const user = cells[0]?.querySelector('.user-cell');
    if (!account || !user) continue;
    const existing = user.querySelector('[data-account-card]');
    // React owns the original name node. Keep its enhanced link in sync after
    // an account edit without recreating the button or its event handler.
    const name = existing ? existing.previousElementSibling : user.lastElementChild;
    if (!name) continue;
    if (existing) {
      if (existing.textContent !== name.textContent) existing.textContent = name.textContent;
      continue;
    }
    const link = button(name.textContent, () => open(account.id), 'account-card-name');
    link.dataset.accountCard = account.id; name.hidden = true; user.append(link);
  }
}

if (typeof document !== 'undefined') {
  const style = element('style');
  style.textContent = `.account-card{width:min(640px,calc(100vw - 24px));max-height:calc(100dvh - 32px);overflow:auto;padding:0;border:1px solid #dce4ef;border-radius:18px;background:#fff;color:#243047}.account-card::backdrop{background:#17243b66}.account-card .workflow-dialog-head{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:20px 24px;border-bottom:1px solid #dce4ef}.account-card .workflow-dialog-head h2{margin:0;font-size:20px}.account-card .workflow-dialog-body{padding:24px;display:grid;gap:16px}.account-card .workflow-dialog-body p,.account-card h3{margin:0}.account-card-fields{display:grid;gap:14px}.account-card .toolbar{display:flex;flex-wrap:wrap;gap:8px}.account-card input{width:100%;min-width:0;box-sizing:border-box}.account-card label{display:grid;gap:8px}.account-card-name{border:0;background:none;padding:6px 0;color:#3156d8;font:inherit;text-align:left;cursor:pointer}.account-card-name:hover{text-decoration:underline}.account-card-name:focus-visible{outline:2px solid #3156d8;outline-offset:3px;border-radius:4px}.account-card section{display:grid;gap:14px}`;
  document.head.append(style);
  let section = null, accounts = [], loading = false, signature = '';
  async function enhance() {
    const management = [...document.querySelectorAll('h2')].find(node => node.textContent === 'Учётные записи управления');
    const tableRoot = management?.closest('section') || management?.parentElement.parentElement;
    const next = tableRoot;
    if (!next) { section = null; accounts = []; signature = ''; return; }
    const nextSignature = [...(tableRoot?.querySelectorAll('tbody tr') || [])].map(row => [...row.querySelectorAll('td')].slice(1,3).map(cell => cell.textContent).join('|')).join('\n');
    if ((next !== section || signature !== nextSignature) && !loading) {
      section = next; signature = nextSignature; loading = true;
      try {
        const data = await accountRequest('');
        if (!next.isConnected) return;
        accounts = data.data;
      } catch { section = next; } finally { loading = false; }
    }
    if (tableRoot) enhanceAccountRows(tableRoot, accounts);
  }
  let queued = false;
  new MutationObserver(() => {
    if (!queued) { queued = true; queueMicrotask(() => { queued = false; enhance(); }); }
  }).observe(document.body, {childList:true, subtree:true});
  enhance();
}
