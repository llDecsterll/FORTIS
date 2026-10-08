// Additive enhancement for the current credential card; never reads its password.
export async function resolveUserLink(login, request, origin) {
  const result = await request(`/api/users?q=${encodeURIComponent(login)}&pageSize=500`);
  const matches = (result.data || []).filter(user => user.email === login);
  if (matches.length !== 1 || !matches[0].id) throw new Error('Не удалось однозначно найти пользователя. Обновите список учётных записей.');
  const data = await request(`/api/users/${encodeURIComponent(matches[0].id)}/panel-link`);
  if (!data.active) throw new Error('Учётная запись отключена. Ссылка входа недоступна.');
  if (typeof data.path !== 'string' || !/^\/[a-f0-9-]{36}\.[A-Za-z0-9_-]{43}\/$/.test(data.path)) throw new Error('Сервер вернул некорректную ссылку входа.');
  return new URL(data.path, origin).href;
}

export async function copyUserLink(text, browserNavigator = navigator, doc = document) {
  if (browserNavigator.clipboard?.writeText) {
    try { await browserNavigator.clipboard.writeText(text); return; } catch { /* HTTP/permission fallback */ }
  }
  const focused = doc.activeElement;
  const input = doc.createElement('textarea');
  input.value = text;
  input.readOnly = true;
  input.style.cssText = 'position:fixed;left:0;top:0;width:1px;height:1px;opacity:0;pointer-events:none;';
  // A modal makes the rest of the document inert, including body-level helpers.
  const container = focused?.closest?.('dialog[open]') || doc.querySelector?.('dialog[open]') || doc.body;
  container.appendChild(input);
  try {
    input.focus?.({preventScroll:true});
    input.select();
    if (!doc.execCommand('copy')) throw new Error('Браузер запретил автоматическое копирование. Покажите нужное поле, выделите текст и нажмите Ctrl+C или ⌘C. Не закрывайте карточку до сохранения пароля.');
  } finally { input.remove(); focused?.focus(); }
}

async function request(path) {
  const token = window.fortisSessionMarker?.() || '';
  const response = await fetch(path, {headers: {}, cache: 'no-store'});
  if (response.status === 401) window.dispatchEvent(new CustomEvent('vpn:unauthorized', {detail:{token}}));
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data?.error?.message || data?.detail || 'Не удалось получить ссылку пользователя.');
  return data;
}

export function enhanceCredentialCards(doc = document) {
  for (const card of doc.querySelectorAll('section[aria-label="Данные новой учётной записи"]')) {
    if (card.querySelector('[data-copy-user-link]')) continue;
    const toolbar = card.querySelector('.toolbar');
    const login = card.querySelector('label input[readonly]');
    if (!toolbar || !login) continue;
    const button = doc.createElement('button');
    button.type = 'button'; button.className = 'btn ghost';
    button.dataset.copyUserLink = '';
    button.textContent = 'Скопировать ссылку пользователя';
    const status = doc.createElement('span');
    status.setAttribute('role', 'status'); status.setAttribute('aria-live', 'polite');
    button.addEventListener('click', async () => {
      const requestedLogin = login.value;
      button.disabled = true; status.textContent = 'Получаем ссылку…';
      try {
        const link = await resolveUserLink(requestedLogin, request, location.origin);
        if (!card.isConnected || login.value !== requestedLogin) return;
        await copyUserLink(link);
        status.textContent = 'Ссылка пользователя скопирована';
      } catch (error) { if (card.isConnected) status.textContent = error.message || 'Не удалось скопировать ссылку'; }
      finally { button.disabled = false; }
    });
    toolbar.append(button, status);
  }
}

if (typeof document !== 'undefined') {
  let queued = false;
  const observer = new MutationObserver(() => {
    if (queued) return;
    queued = true;
    queueMicrotask(() => { queued = false; enhanceCredentialCards(); });
  });
  observer.observe(document.body, {childList:true, subtree:true});
  enhanceCredentialCards();
}
