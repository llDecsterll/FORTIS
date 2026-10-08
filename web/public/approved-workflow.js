(() => {
  const releaseVersion = document.querySelector('meta[name="app-version"]')?.content || 'dev';
  if (!document.getElementById("approval-status-theme")) {
    const style = document.createElement("link");
    style.id = "approval-status-theme";
    style.rel = "stylesheet";
    style.href = window.panelUrl(`/approval-status.css?v=${encodeURIComponent(releaseVersion)}`);
    document.head.appendChild(style);
  }
  const OPERATORS = new Set(["ADMIN", "IT_LEAD", "IT_STAFF"]);
  const APPROVERS = new Set(["ADMIN", "IT_LEAD"]);
  let me = null;
  let disposeApprovals = null;
  let usersCategory = "all";
  let usersDepartment = "";
  let usersVpnFilter = "all";
  let usersSearch = "";
  let scheduled = 0;
  let usersRefreshTimer = 0;
  let countdownTimer = 0;

  const token = () => window.fortisSessionMarker?.() || '';
  const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[char]);

  async function api(path, options = {}) {
    const headers = new Headers(options.headers || {});
    const requestToken = token();

    if (options.body && !(options.body instanceof FormData)) headers.set("Content-Type", "application/json");
    const response = await fetch(path, { ...options, headers });
    if (response.status === 401) window.dispatchEvent(new CustomEvent('vpn:unauthorized', { detail: { token: requestToken } }));
    const type = response.headers.get("content-type") || "";
    const data = type.includes("application/json") ? await response.json() : await response.blob();
    if (!response.ok) throw new Error(data?.error?.message || data?.detail || "Операция не выполнена");
    return data;
  }

  function notice(message, kind = "ok") {
    let node = document.getElementById("workflow-notice");
    if (!node) {
      node = document.createElement("div");
      node.id = "workflow-notice";
      document.body.appendChild(node);
    }
    node.className = `workflow-notice ${kind}`;
    node.textContent = message;
    node.hidden = false;
    window.setTimeout(() => { node.hidden = true; }, 4200);
  }

  function closeDialog(dialog) {
    dialog.close();
    dialog.remove();
  }

  async function copyConfig(text) {
    try { await navigator.clipboard.writeText(text); return; } catch (_) {}
    const field = document.createElement("textarea");
    field.value = text;
    field.setAttribute("aria-label", "Конфигурация для копирования");
    field.style.position = "fixed";
    field.style.opacity = "0";
    (document.querySelector("dialog[open]") || document.body).appendChild(field);
    field.select();
    const copied = document.execCommand("copy");
    field.remove();
    if (!copied) throw new Error("Браузер запретил копирование. Разрешите доступ к буферу обмена или скачайте конфигурацию.");
  }

  function dialogShell(title) {
    const dialog = document.createElement("dialog");
    dialog.className = "workflow-dialog";
    dialog.setAttribute("aria-label", title);
    dialog.innerHTML = `<div class="workflow-dialog-head"><h2>${escapeHtml(title)}</h2><button type="button" class="workflow-icon-button" aria-label="Закрыть">×</button></div><div class="workflow-dialog-body"></div>`;
    dialog.querySelector(".workflow-icon-button").addEventListener("click", () => closeDialog(dialog));
    dialog.addEventListener("cancel", (event) => { event.preventDefault(); closeDialog(dialog); });
    document.body.appendChild(dialog);
    dialog.addEventListener("close", () => dialog.remove(), { once: true });
    dialog.showModal();
    return dialog;
  }

  function requestData(form) {
    const data = new FormData(form);
    if (form.querySelector('[data-employee-networks]')) {
      const selected = data.getAll('networkIds');
      if (!selected.length) throw new Error('Выберите хотя бы одну доступную сеть');
      data.set('networkIds', JSON.stringify(selected));
    }
    const value = data.get("accessUntil");
    const date = value ? new Date(`${value}:00+03:00`) : null;
    if (!date || !Number.isFinite(date.getTime()) || date.getTime() <= Date.now()) {
      throw new Error("Укажите будущую дату и время окончания доступа (МСК)");
    }
    data.set("accessUntil", date.toISOString());
    return data;
  }

  function termLabel(value) {
    if (!value) return "Срок не указан";
    const normalized = /(?:Z|[+-]\d\d:\d\d)$/.test(value) ? value : `${value}Z`;
    return `До ${new Date(normalized).toLocaleString("ru-RU", { timeZone: "Europe/Moscow", dateStyle: "short", timeStyle: "short" })} МСК`;
  }

  function openRenewal(user) {
    const dialog = dialogShell("Продлить VPN");
    const body = dialog.querySelector('.workflow-dialog-body');
    body.innerHTML = `<p><strong>${escapeHtml(user.fullName)}</strong></p><p>Текущий доступ: ${escapeHtml(termLabel(user.accessUntil))}</p><form class="workflow-form"><label>Новый срок доступа (МСК) *<input name="accessUntil" type="datetime-local" required /></label><p class="workflow-help">Срок изменится только после решения в разделе «Согласование». Существующий ключ сохранится.</p><p role="alert" data-renewal-error></p><div class="workflow-form-actions"><button type="button" class="workflow-secondary" data-cancel>Отмена</button><button type="submit" class="workflow-primary">Подать на согласование</button></div></form>`;
    const form = body.querySelector('form');
    body.querySelector('[data-cancel]').onclick = () => dialog.close();
    const send = async () => {
      const controls = form.querySelectorAll('button');
      controls.forEach(c => c.disabled = true);
      try {
        await api(`/api/users/${encodeURIComponent(user.id)}/renewal`, {method:'POST', body:requestData(form)});
        dialog.close();
        notice('Продление отправлено на согласование');
        window.dispatchEvent(new Event('vpn:approvals-changed'));
        if (window.panelRoute() === '/users') await renderUsersPage();
      } catch (error) {
        body.querySelector('[data-renewal-error]').textContent = error.message;
        controls.forEach(c => c.disabled = false);
      }
    };
    form.onsubmit = event => { event.preventDefault(); send(); };
  }

  async function openVpnSettings(user) {
    const dialog = dialogShell('Редактировать VPN сотрудника');
    const body = dialog.querySelector('.workflow-dialog-body');
    body.innerHTML = '<p role="status">Загрузка настроек VPN…</p>';
    try {
      const settings = await api(`/api/users/${encodeURIComponent(user.id)}/vpn-settings`);
      if (!dialog.isConnected) return;
      const selected = new Set(settings.networkIds);
      const date = settings.accessUntil ? new Date(new Date(settings.accessUntil).getTime() + 3 * 3600000).toISOString().slice(0, 16) : '';
      body.innerHTML = `<p><strong>${escapeHtml(user.fullName)}</strong></p><form class="workflow-form"><label>Доступ до — дата и время (МСК) *<input name="accessUntil" type="datetime-local" value="${escapeHtml(date)}" required /></label><fieldset><legend>Дополнительные сети</legend><div class="workflow-network-options">${settings.networks.map(n => `<label class="workflow-network-option"><input type="checkbox" name="networkIds" value="${escapeHtml(n.id)}" ${selected.has(n.id) ? 'checked' : ''} /><span>${escapeHtml(n.name)} <small>${escapeHtml(n.cidr)}</small></span></label>`).join('')}</div>${settings.networks.length ? '' : '<p>Дополнительных сетей нет.</p>'}</fieldset>${settings.automaticNetworks.length ? `<details><summary>Автоматически доступны: ${settings.automaticNetworks.length} сетей</summary><p class="workflow-help">Главная сеть и сети активных объектов доступны по общей политике независимо от отметок выше.</p><ul>${settings.automaticNetworks.map(cidr => `<li>${escapeHtml(cidr)}</li>`).join('')}</ul></details>` : '<p class="workflow-help">Выберите хотя бы одну сеть.</p>'}<p class="workflow-help">Ключ VPN сохранится. После изменения сетей скачайте обновлённую конфигурацию и примените её на компьютере сотрудника. Приостановленный VPN автоматически не включится.</p><p role="alert" data-error></p><div class="workflow-form-actions"><button type="button" class="workflow-secondary" data-cancel>Отмена</button><button type="submit" class="workflow-primary">Сохранить изменения</button></div></form>`;
      const form = body.querySelector('form');
      const memoForm = document.createElement('form');
      memoForm.className = 'workflow-form';
      memoForm.innerHTML = '<fieldset><legend>Служебная записка</legend><div data-memo-current></div><label>Новая служебная записка PDF (до 15 МБ)<input type="file" name="file" accept="application/pdf,.pdf" required /></label><p class="workflow-help">Замена сохраняется отдельно. Прежняя записка останется в истории; согласование, срок и ключ VPN не изменятся.</p><p role="alert" data-memo-error></p><p role="status" data-memo-status></p><button type="submit" class="workflow-secondary">Заменить служебную записку</button></fieldset>';
      form.before(memoForm);
      let memoVersion = settings.memoVersion;
      const showMemos = docs => {
        const container = memoForm.querySelector('[data-memo-current]');
        container.replaceChildren();
        for (const doc of docs || []) {
          const button = document.createElement('button');
          button.type = 'button'; button.className = 'workflow-secondary';
          button.textContent = doc.filename || 'Открыть служебную записку';
          button.onclick = () => previewDocument(doc.id, doc.filename);
          container.appendChild(button);
        }
      };
      showMemos(settings.documents);
      memoForm.onsubmit = async event => {
        event.preventDefault();
        const submit = memoForm.querySelector('[type="submit"]');
        const error = memoForm.querySelector('[data-memo-error]');
        const status = memoForm.querySelector('[data-memo-status]');
        const file = memoForm.querySelector('[name="file"]').files[0];
        error.textContent = ''; status.textContent = '';
        if (!file || !file.name.toLowerCase().endsWith('.pdf') || file.size > 15 * 1024 * 1024) {
          error.textContent = 'Выберите PDF размером до 15 МБ'; return;
        }
        submit.disabled = true;
        try {
          const data = new FormData(memoForm); data.set('version', memoVersion);
          const result = await api(`/api/users/${encodeURIComponent(user.id)}/memo`, {method: 'POST', body: data});
          memoVersion = result.memoVersion; showMemos(result.documents); memoForm.reset();
          status.textContent = 'Служебная записка заменена. VPN не изменён.';
          await renderUsersPage();
        } catch (err) { error.textContent = err.message; }
        finally { submit.disabled = false; }
      };
      const deadline = form.querySelector('[name="accessUntil"]');
      if (date) deadline.max = date;
      const renewalHint = document.createElement('p');
      renewalHint.className = 'workflow-help';
      renewalHint.textContent = 'Здесь можно сохранить или сократить срок. Для увеличения используйте «Продлить VPN» — заявка поступит в раздел «Согласование».';
      deadline.closest('label').after(renewalHint);
      body.querySelector('[data-cancel]').onclick = () => closeDialog(dialog);
      form.onsubmit = async event => {
        event.preventDefault();
        const submit = form.querySelector('[type="submit"]');
        const error = form.querySelector('[data-error]');
        submit.disabled = true; error.textContent = '';
        try {
          const data = requestData(form);
          const networkIds = data.getAll('networkIds');
          if (!networkIds.length && !settings.automaticNetworks.length) throw new Error('Выберите хотя бы одну сеть');
          await api(`/api/users/${encodeURIComponent(user.id)}/vpn-settings`, {method:'PATCH', body:JSON.stringify({accessUntil:data.get('accessUntil'), networkIds, version:settings.version})});
          closeDialog(dialog);
          notice('Настройки сохранены. После изменения сетей примените обновлённую VPN-конфигурацию.');
          await renderUsersPage();
        } catch (err) { error.textContent = err.message; submit.disabled = false; }
      };
      form.querySelector('[name="accessUntil"]').focus();
    } catch (err) {
      body.innerHTML = `<p role="alert">${escapeHtml(err.message)}</p><p>Закройте форму и повторите попытку.</p>`;
    }
  }

  function openVpnPause(user) {
    const resume = Boolean(user.suspended);
    const title = resume ? 'Возобновить VPN' : 'Приостановить VPN';
    const dialog = dialogShell(title);
    const body = dialog.querySelector('.workflow-dialog-body');
    body.innerHTML = `<p><strong>${escapeHtml(user.fullName)}</strong></p><p>${resume ? 'VPN-доступ будет возобновлён с прежним ключом и настройками.' : 'Активное VPN-подключение прекратится. Ключ, срок и выбранные сети сохранятся. Возобновить доступ сможет Администратор или Руководитель ИТ.'}</p><p role="alert" data-error></p><div class="workflow-form-actions"><button type="button" class="workflow-secondary" data-cancel>Отмена</button><button type="button" class="workflow-primary" data-confirm>${title}</button></div>`;
    body.querySelector('[data-cancel]').onclick = () => closeDialog(dialog);
    body.querySelector('[data-cancel]').focus();
    body.querySelector('[data-confirm]').onclick = async event => {
      const submit = event.currentTarget;
      submit.disabled = true;
      try {
        await api(`/api/users/${encodeURIComponent(user.id)}/${resume ? 'resume' : 'suspend'}`, {method:'POST'});
        closeDialog(dialog); notice(resume ? 'VPN возобновлён' : 'VPN приостановлен');
        await renderUsersPage();
      } catch (error) { body.querySelector('[data-error]').textContent = error.message; submit.disabled = false; }
    };
  }

  async function loadEmployeeNetworks(form) {
    const field = form.querySelector('[data-employee-networks]');
    const submit = form.querySelector('[type="submit"]');
    submit.disabled = true;
    try {
      const result = await api('/api/networks?contour=EMPLOYEES');
      const networks = (result.data || []).filter(n => n.employeeSelectable === true);
      field.innerHTML = `<legend>Доступные сети *</legend><p class="workflow-help">Отметьте сети, к которым сотруднику нужен доступ. Неотмеченные сети в VPN-конфигурацию и правила доступа не включаются.</p><div class="workflow-network-options">${networks.map(n => `<label class="workflow-network-option"><input type="checkbox" name="networkIds" value="${escapeHtml(n.id)}" /><span>${escapeHtml(n.name)} <small>${escapeHtml(n.cidr)}</small></span></label>`).join('')}</div>${networks.length ? '' : '<p role="alert">Нет доступных сетей сотрудников. Добавьте сеть в разделе «Сети и ресурсы».</p>'}<p role="alert" data-network-error></p>`;
      submit.disabled = !networks.length;
    } catch (error) {
      field.innerHTML = `<legend>Доступные сети *</legend><p role="alert">${escapeHtml(error.message)}</p><p>Закройте форму и повторите попытку.</p>`;
    }
  }

  async function openEmployeeRequest(preselectedId = "") {
    const dialog = dialogShell("Заявка на VPN для сотрудника");
    const body = dialog.querySelector(".workflow-dialog-body");
    body.innerHTML = '<p class="workflow-muted" role="status">Загрузка списка сотрудников…</p>';
    try {
      const result = await api("/api/users?pageSize=500");
      const users = (result.data || []).filter((user) => user.role === "USER");
      body.innerHTML = `
        <form class="workflow-form">
          <label>Сотрудник<select name="userId" required><option value="">Выберите сотрудника</option>${users.map((user) => `<option value="${escapeHtml(user.id)}" ${user.id === preselectedId ? "selected" : ""}>${escapeHtml(user.fullName)} · ${escapeHtml(user.company || "Компания не указана")} · ${escapeHtml(user.department || "Отдел не указан")}</option>`).join("")}</select></label>
          <label>Основание<textarea name="reason" rows="3">VPN-доступ сотрудника</textarea></label>
          <fieldset data-employee-networks><legend>Доступные сети *</legend><p role="status">Загрузка сетей…</p></fieldset>
          <label>Доступ до — дата и время (МСК) *<input name="accessUntil" type="datetime-local" required /></label>
          <label>Рабочий ПК для RDP<input name="rdpHost" placeholder="192.168.1.25" /></label>
          <label>Логин RDP<input name="rdpUser" placeholder="DOMAIN\\user" /></label>
          <label>Пароль RDP<input name="rdpPassword" type="password" autocomplete="new-password" /></label>
          <label>Порт RDP<input name="rdpPort" type="number" min="1" max="65535" value="3389" /></label>
          <p class="workflow-help">После указанного срока VPN будет автоматически заблокирован, даже если ключ ещё не использовался.</p>
          <label>Служебная записка PDF <span aria-hidden="true">*</span><input name="file" type="file" accept="application/pdf,.pdf" required /></label>
          <p class="workflow-help">Без служебной записки заявку нельзя отправить и согласовать.</p>
          <div class="workflow-form-actions"><button type="button" class="workflow-secondary">Отмена</button><button type="submit" class="workflow-primary">Подать на согласование</button></div>
        </form>`;
      const form = body.querySelector("form");
      await loadEmployeeNetworks(form);
      form.querySelector(".workflow-secondary").addEventListener("click", () => closeDialog(dialog));
      form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const submit = form.querySelector('[type="submit"]');
        submit.disabled = true;
        try {
          await api("/api/requests/employee", { method: "POST", body: requestData(form) });
          closeDialog(dialog);
          notice("Заявка отправлена на согласование");
          window.dispatchEvent(new Event('vpn:approvals-changed'));
          if (window.panelRoute() === "/users") await renderUsersPage();
          else schedule();
        } catch (error) {
          form.querySelector('[data-network-error]').textContent = error.message;
          submit.disabled = false;
        }
      });
      form.querySelector("select")?.focus();
    } catch (error) {
      body.innerHTML = `<p class="workflow-error">${escapeHtml(error.message)}</p>`;
    }
  }

  async function openManualRequest() {
    const dialog = dialogShell("Создать VPN-заявку вручную");
    const body = dialog.querySelector(".workflow-dialog-body");
    body.innerHTML = `
      <form class="workflow-form">
        <div class="workflow-grid">
          <label>ФИО<input name="fullName" required autocomplete="name" /></label>
          <label>Электронная почта<input name="email" type="email" autocomplete="email" placeholder="Можно оставить пустой" /></label>
          <label>Компания<input name="companyName" required /></label>
          <label>Отдел<input name="departmentName" required /></label>
          <label>Должность<input name="title" /></label>
          <label>Категория<select name="isManagement"><option value="false">Пользователь</option><option value="true">Руководство</option></select></label>
          <label>Доступ до — дата и время (МСК) *<input name="accessUntil" type="datetime-local" required /></label>
        </div>
        <fieldset data-employee-networks><legend>Доступные сети *</legend><p role="status">Загрузка сетей…</p></fieldset>
        <label>Служебная записка PDF <span aria-hidden="true">*</span><input name="files" type="file" accept="application/pdf,.pdf" required /></label>
        <p class="workflow-help">VPN-ключ будет создан только после решения в разделе «Согласование».</p>
        <div class="workflow-form-actions"><button type="button" class="workflow-secondary">Отмена</button><button type="submit" class="workflow-primary">Подать на согласование</button></div>
      </form>`;
    const form = body.querySelector("form");
    await loadEmployeeNetworks(form);
    form.querySelector(".workflow-secondary").addEventListener("click", () => closeDialog(dialog));
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const submit = form.querySelector('[type="submit"]');
      submit.disabled = true;
      try {
        await api("/api/users/employee", { method: "POST", body: requestData(form) });
        closeDialog(dialog);
        notice("Ручная заявка создана и отправлена на согласование");
        window.dispatchEvent(new Event('vpn:approvals-changed'));
        if (window.panelRoute() === "/users") await renderUsersPage();
        else schedule();
      } catch (error) {
        form.querySelector('[data-network-error]').textContent = error.message;
        submit.disabled = false;
      }
    });
    form.querySelector("input")?.focus();
  }

  async function previewDocument(documentId, filename) {
    window.dispatchEvent(new CustomEvent("vpn:preview-document", {
      detail: { id: documentId, filename: filename || "Служебная записка.pdf" },
    }));
  }

  async function openConfig(row) {
    if (row.siteId) return openRouterSetup(row.siteId, row.subjectName);
    const path = row.siteId ? `/api/sites/${encodeURIComponent(row.siteId)}/vpn` : `/api/users/${encodeURIComponent(row.userId)}/vpn`;
    try {
      const vpn = await api(path);
      const dialog = dialogShell(`VPN-конфигурация · ${row.subjectName}`);
      const body = dialog.querySelector(".workflow-dialog-body");
      body.innerHTML = `<p class="workflow-help">Конфигурация выдана после согласования. Передача третьим лицам запрещена.</p><pre class="workflow-config"></pre><div class="workflow-form-actions"><button type="button" class="workflow-secondary" data-copy>Копировать</button><button type="button" class="workflow-primary" data-download>Скачать .conf</button></div>`;
      body.querySelector("pre").textContent = vpn.config || "";
      body.querySelector("[data-copy]").addEventListener("click", async () => {
        await copyConfig(vpn.config || "");
        notice("Конфигурация скопирована");
      });
      body.querySelector("[data-download]").addEventListener("click", async () => {
        const endpoint = row.siteId ? `/api/sites/${encodeURIComponent(row.siteId)}/wireguard.conf` : `/api/users/${encodeURIComponent(row.userId)}/wireguard.conf`;
        const blob = await api(endpoint);
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = vpn.filename || "wireguard.conf";
        link.click();
        URL.revokeObjectURL(url);
      });
    } catch (error) {
      notice(error.message, "error");
    }
  }

  // A fresh authorized request is required on every opening; no keys in persistent storage.
  async function openRouterSetup(siteId, subjectName) {
    try {
      const [vpn, sites, builder, actor, routing] = await Promise.all([
        api(`/api/sites/${encodeURIComponent(siteId)}/vpn`), api('/api/sites'),
        import(window.panelUrl(`/router-setup.mjs?v=${encodeURIComponent(releaseVersion)}`)), api('/api/auth/me'),
        api(`/api/sites/${encodeURIComponent(siteId)}/routing`),
      ]);
      const site = sites.data.find(item => item.id === siteId);
      if (!site) throw new Error('Объект не найден');
      const dialog = dialogShell(`Настроить роутер · ${subjectName || site.name}`);
      const body = dialog.querySelector('.workflow-dialog-body');
      let configured=false, routerChosen=false;
      body.innerHTML = `<p class="workflow-help">1. Подсеть роутера → 2. Сети назначения → 3. Выбор роутера → 4. Конфигурация. Действующий VPN-ключ сохраняется.</p>
        <form data-lan-form class="workflow-form">
          <h3>1. Какая подсеть за подключаемым роутером?</h3>
          <label>Локальные сети роутера <span aria-hidden="true">*</span>
            <input name="lanCidr" aria-label="Локальные сети роутера" value="${escapeHtml(site.lanCidr || '')}" placeholder="192.168.88.0/24, 172.16.50.0/24" required maxlength="2048" ${OPERATORS.has(actor.role)?'':'readonly'} />
          </label>
          <p class="workflow-help">Укажите адреса сетей за роутером, не VPN IP и не адрес самого роутера. Несколько подсетей — через запятую. ${OPERATORS.has(actor.role)?'Сохранение обновит маршруты и правила сервера без смены ключа.':'Изменять сети могут Администратор, Руководитель ИТ и Сотрудник ИТ.'}</p>
          <fieldset data-destinations><legend>2. В какие сети нужен доступ?</legend>
          <p class="workflow-help">Выберите разрешённые сети на стороне сервера. В конфигурацию и правила доступа попадут только выбранные сети. Служебный адрес VPN-сервера добавляется автоматически.</p>
          ${routing.available.map(cidr=>`<label class="workflow-check"><input type="checkbox" name="destination" value="${escapeHtml(cidr)}" ${routing.selected.includes(cidr)?'checked':''} ${OPERATORS.has(actor.role)?'':'disabled'} /> <span>${escapeHtml(cidr)}</span></label>`).join('')}
          ${routing.available.length?'':'<p role="alert">Нет разрешённых сетей назначения. Обратитесь к Администратору.</p>'}
          ${OPERATORS.has(actor.role)?`<details data-add-network><summary>Добавить сеть назначения</summary><label>Название сети<input data-network-name maxlength="200" placeholder="Офис" /></label><label>Подсеть или IP с маской<input data-network-cidr placeholder="192.168.230.17/28" maxlength="40" /></label><p class="workflow-help">IP с маской преобразуется в адрес подсети. Сеть появится в каталоге объектов. Доступ применяется после сохранения выбранных сетей.</p><button type="button" class="workflow-secondary" data-create-network>Добавить сеть</button><p data-network-status role="status"></p></details>`:''}
          <button type="submit" class="workflow-primary">${OPERATORS.has(actor.role)?'Сохранить сети и сформировать конфигурацию':'Сформировать сохранённую конфигурацию'}</button>
          </fieldset>
          <p data-lan-status role="status"></p>
        </form><section data-router-choice hidden aria-label="Выбор роутера"><h3 tabindex="-1" data-choice-heading>3. Выберите роутер</h3><p class="workflow-help">Сети сохранены. Для какого роутера подготовить конфигурацию?</p><div class="workflow-form-actions"><button type="button" class="workflow-primary" data-choose-router="mikrotik">MikroTik · RouterOS 7</button><button type="button" class="workflow-primary" data-choose-router="keenetic">Keenetic · WireGuard VPN</button></div><button type="button" class="workflow-secondary" data-back-networks>Назад к сетям</button></section>
        <section data-config-stage hidden><h3 tabindex="-1" data-config-heading>4. Конфигурация роутера</h3><button type="button" class="workflow-secondary" data-back-router>Выбрать другой роутер</button><label>Имя файла конфигурации (без .conf)<input data-config-name value="${escapeHtml((vpn.filename || 'site.conf').replace(/\.conf$/,''))}" maxlength="15" autocomplete="off" spellcheck="false" /></label><p class="workflow-help">1–15 латинских букв, цифр, дефисов или подчёркиваний. Имя сохраняется для объекта; VPN-ключ не меняется.</p><button type="button" class="workflow-secondary" data-save-config-name>Сохранить имя</button><p data-config-name-status role="status"></p><div class="router-fields">
          <label>Роутер<select data-router><option value="mikrotik">MikroTik · RouterOS 7</option><option value="keenetic">Keenetic · WireGuard VPN</option></select></label>
          <label>Способ настройки<select data-method><option value="graphical">Графический интерфейс</option><option value="terminal">Терминал</option></select></label>
          <label>Имя интерфейса<input data-interface value="${escapeHtml(String(vpn.configName || 'MSK-GK-TSI').replace(/[^A-Za-z0-9_-]/g, '-').replace(/^[^A-Za-z]+/, 'WG-').slice(0,20))}" autocomplete="off" spellcheck="false" readonly /></label>
        </div><div data-result aria-live="polite"></div></section>`;
      const resultNode=body.querySelector('[data-result]');
      const lanForm=body.querySelector('[data-lan-form]');
      const lanInput=lanForm.querySelector('input');
      const lanStatus=lanForm.querySelector('[data-lan-status]');
      const selected=()=>Array.from(lanForm.querySelectorAll('[name="destination"]:checked')).map(el=>el.value);
      const invalidate=()=>{configured=false;routerChosen=false;body.querySelector('[data-router-choice]').hidden=true;body.querySelector('[data-config-stage]').hidden=true;resultNode.replaceChildren();};
      lanInput.addEventListener('input',()=>{invalidate();});
      lanForm.querySelectorAll('[name="destination"]').forEach(el=>el.addEventListener('change',invalidate));
      const createNetwork=body.querySelector('[data-create-network]');
      if(createNetwork) createNetwork.onclick=async()=>{
        const status=body.querySelector('[data-network-status]');
        createNetwork.disabled=true;status.textContent='Добавление…';
        try {
          const added=await api(`/api/sites/${encodeURIComponent(siteId)}/networks`,{method:'POST',body:JSON.stringify({name:body.querySelector('[data-network-name]').value.trim(),cidr:body.querySelector('[data-network-cidr]').value.trim()})});
          const label=document.createElement('label');label.className='workflow-check';
          const checkbox=document.createElement('input');checkbox.type='checkbox';checkbox.name='destination';checkbox.value=added.cidr;checkbox.checked=true;checkbox.addEventListener('change',invalidate);
          const text=document.createElement('span');text.textContent=`${added.name} (${added.cidr})`;
          label.append(checkbox,text);body.querySelector('[data-add-network]').before(label);
          routing.available.push(added.cidr);invalidate();status.textContent=`Добавлена ${added.cidr}. Сохраните сети, чтобы применить доступ.`;
        } catch(error) {status.textContent=error.message;}
        finally {createNetwork.disabled=false;}
      };
      body.querySelector('[data-save-config-name]').onclick=async()=>{
        const button=body.querySelector('[data-save-config-name]'),status=body.querySelector('[data-config-name-status]');
        button.disabled=true;status.textContent='Сохранение…';
        try {
          const saved=await api(`/api/sites/${encodeURIComponent(siteId)}/config-name`,{method:'PUT',body:JSON.stringify({name:body.querySelector('[data-config-name]').value.trim()})});
          vpn.filename=saved.filename;body.querySelector('[data-config-name]').value=saved.filename.replace(/\.conf$/,'');status.textContent=`Сохранено: ${saved.filename}`;
        } catch(error) {status.textContent=error.message;}
        finally {button.disabled=false;}
      };
      lanForm.addEventListener('submit',async(event)=>{
        event.preventDefault();
        if(!selected().length){lanStatus.textContent='Выберите хотя бы одну сеть назначения.';return;}
        if(site.lanCidr && lanInput.value.trim()===site.lanCidr.trim() && JSON.stringify([...selected()].sort())===JSON.stringify([...routing.selected].sort())) {
          configured=true;lanStatus.textContent='Используется сохранённая настройка. Маршруты и VPN-ключ не изменены.';render();return;
        }
        if(!OPERATORS.has(actor.role)) {configured=!!site.lanCidr && routing.selected.length>0;render();return;}
        const submit=lanForm.querySelector('[type="submit"]');
        submit.disabled=true; lanInput.readOnly=true;
        lanStatus.textContent='Проверка и сохранение подсетей…';
        resultNode.replaceChildren();
        try {
          const result=await api(`/api/sites/${encodeURIComponent(siteId)}/lan`,{method:'PUT',body:JSON.stringify({lanCidr:lanInput.value.trim(),destinations:selected()})});
          const refreshed=await api(`/api/sites/${encodeURIComponent(siteId)}/vpn`);
          site.lanCidr=result.lanCidr; lanInput.value=result.lanCidr;
          Object.assign(vpn,refreshed);
          routing.selected=result.destinations;configured=true;
          lanStatus.textContent='Обе стороны соединения сохранены. Выберите роутер.';
        } catch(error) { lanStatus.textContent=error.message; }
        finally { submit.disabled=false; lanInput.readOnly=false; render(); }
      });
      const download=(name,content)=>{
        const url=URL.createObjectURL(new Blob([content],{type:'text/plain;charset=utf-8'}));
        const link=document.createElement('a'); link.href=url; link.download=name;
        link.hidden=true; dialog.appendChild(link); link.click(); link.remove();
        setTimeout(()=>URL.revokeObjectURL(url),30000);
      };
      function render() {
        try {
          lanForm.hidden=configured;
          body.querySelector('[data-router-choice]').hidden=!configured || routerChosen;
          body.querySelector('[data-config-stage]').hidden=!configured || !routerChosen;
          if(!configured) return;
          if(!routerChosen) {resultNode.replaceChildren();body.querySelector('[data-choice-heading]').focus();return;}
          if(!site.lanCidr || lanInput.value.trim() !== site.lanCidr.trim()) {
            resultNode.innerHTML='<p class="router-warning">Перед формированием конфигурации укажите и сохраните локальные сети роутера. Несохранённые значения не применяются.</p>';
            return;
          }
          const brand=body.querySelector('[data-router]').value, method=body.querySelector('[data-method]').value;
          const result=builder.routerSetup(vpn.config || '',site.lanCidr || '',brand,body.querySelector('[data-interface]').value.trim());
          const guide=builder.setupGuide(result,brand,method);
          const webCli=brand==='keenetic' && method==='terminal';
          resultNode.innerHTML=`<p><strong>VPN IP:</strong> ${escapeHtml(result.address)} · <strong>Сервер:</strong> ${escapeHtml(result.endpoint)}</p>
            <p><strong>Подсети объекта:</strong> ${escapeHtml(result.lans.join(', ') || 'Не указаны')}</p>
            ${result.warnings.map(x=>`<p class="router-warning">${escapeHtml(x)}</p>`).join('')}
            <details><summary>Все маршруты VPN (${result.routes.length})</summary><ul class="router-routes">${result.routes.map(net=>`<li><code>${escapeHtml(net)}</code> → ${escapeHtml(result.iface)}</li>`).join('')}</ul></details>
            <h3>Пошаговая настройка</h3><ol class="router-guide">${guide.map(x=>`<li>${escapeHtml(x)}</li>`).join('')}</ol>
            <div class="workflow-form-actions">${!webCli?'<button class="workflow-primary" data-conf>Скачать .conf для импорта</button>':''}${brand==='mikrotik'?'<button type="button" class="workflow-primary" data-rsc>Скачать .rsc для MikroTik</button><button type="button" class="workflow-secondary" data-copy-script>Скопировать команды</button>':''}<button class="workflow-secondary" data-guide>Скачать инструкцию</button></div><p role="status" data-script-status></p>
            ${brand==='keenetic'&&!webCli?'<p class="router-warning">Файл .conf загружается через создание подключения WireGuard → «Загрузить из файла». Не вставляйте содержимое файла в Web CLI. Для ввода команд выберите «Web CLI · по одной команде».</p>':''}
            ${webCli?`<section aria-label="Команды Web CLI"><h3>Web CLI: одна команда — один запрос</h3><p class="router-warning">Не вставляйте весь файл в /a. Копируйте по одной, отправляйте и проверяйте ответ. При ошибке остановитесь. Команды с ключами скрыты до раскрытия.</p><ol class="router-command-list">${result.commands.map((command,index)=>`<li><details><summary>Команда ${index+1}${/private-key|preshared-key/.test(command)?' · содержит секретный ключ':''}</summary><pre class="workflow-config" data-command-text="${index}"></pre></details><button type="button" class="workflow-secondary" data-copy-command="${index}">Копировать команду ${index+1}</button><span role="status" data-command-status="${index}"></span></li>`).join('')}</ol></section>`:`<details><summary>Показать ${method==='terminal'?'команды':'конфигурацию'} (содержит закрытый ключ)</summary><pre class="workflow-config" data-code></pre><button class="workflow-secondary" data-copy-code>Копировать ${method==='terminal'?'команды':'конфигурацию'}</button></details>`}
            <p class="workflow-help">${brand==='keenetic'?'Справочник CLI: KeeneticOS 4.3. Названия экранов зависят от версии.':'Для RouterOS 6 сначала требуется обновление до поддерживаемой RouterOS 7.'} Проверка на вашем физическом роутере ещё не выполнена.</p>`;
          if(webCli) {
            resultNode.querySelectorAll('[data-command-text]').forEach(el=>{el.textContent=result.commands[Number(el.dataset.commandText)];});
            resultNode.querySelectorAll('[data-copy-command]').forEach(button=>{button.onclick=async()=>{
              const index=Number(button.dataset.copyCommand),status=resultNode.querySelector(`[data-command-status="${index}"]`);
              try {await copyConfig(result.commands[index]);status.textContent='Скопировано. Отправьте в Web CLI и проверьте ответ.';}
              catch(error){status.textContent=error.message;}
            };});
          } else resultNode.querySelector('[data-code]').textContent=method==='terminal'?result.script:result.config;
          if(!webCli) resultNode.querySelector('[data-conf]').onclick=()=>download(vpn.filename || 'site.conf',result.config);
          if(brand==='mikrotik') resultNode.querySelector('[data-copy-script]').onclick=async()=>{
            const status=resultNode.querySelector('[data-script-status]');
            try { await copyConfig(result.script); status.textContent='Команды скопированы. Вставьте их в терминал роутера.'; }
            catch(error) { status.textContent=error.message; }
          };
          if(brand==='mikrotik') resultNode.querySelector('[data-rsc]').onclick=()=>download(`${result.iface}-wireguard-setup.rsc`,result.script);
          resultNode.querySelector('[data-guide]').onclick=()=>download('router-guide.txt',guide.map((x,n)=>`${n+1}. ${x}`).join('\n\n')+'\n\nМаршруты:\n'+result.routes.join('\n'));
          if(!webCli) resultNode.querySelector('[data-copy-code]').onclick=async()=>{
            try { await copyConfig(method==='terminal'?result.script:result.config); notice('Скопировано'); }
            catch(error) { notice(error.message,'error'); }
          };
        } catch(error) { resultNode.innerHTML=`<p role="alert" class="router-warning">${escapeHtml(error.message)}</p>`; }
      }
      body.querySelector('[data-router]').onchange=()=>{
        body.querySelector('[data-method] option[value="terminal"]').textContent=body.querySelector('[data-router]').value==='keenetic'?'Web CLI · по одной команде':'Терминал';
        if(body.querySelector('[data-router]').value==='keenetic') body.querySelector('[data-method]').value='terminal';
        body.querySelector('[data-interface]').value=String(vpn.configName || 'MSK-GK-TSI').replace(/[^A-Za-z0-9_-]/g, '-').replace(/^[^A-Za-z]+/, 'WG-').slice(0,20); render();
      };
      body.querySelector('[data-method]').onchange=render;
      body.querySelector('[data-interface]').onchange=render;
      body.querySelectorAll('[data-choose-router]').forEach(button=>{button.onclick=()=>{
        if(!configured) return;
        routerChosen=true;
        body.querySelector('[data-router]').value=button.dataset.chooseRouter;
        body.querySelector('[data-method]').value=button.dataset.chooseRouter==='keenetic'?'terminal':'graphical';
        body.querySelector('[data-router]').onchange();
        body.querySelector('[data-config-heading]').focus();
      };});
      body.querySelector('[data-back-router]').onclick=()=>{routerChosen=false;render();};
      body.querySelector('[data-back-networks]').onclick=()=>{invalidate();render();lanInput.focus();};
      render();
    } catch(error) { notice(error.message,'error'); }
  }
  window.addEventListener('vpn:setup-router',event=>{
    if(event.detail?.siteId) openRouterSetup(event.detail.siteId,event.detail.name);
  });

  function pageHost() {
    const original = document.querySelector("main") || document.querySelector(".content");
    if (!original) return null;
    let host = document.getElementById("workflow-page-host");
    if (!host) {
      host = document.createElement("div");
      host.id = "workflow-page-host";
      host.className = original.className;
      host.setAttribute("role", "main");
      host.tabIndex = -1;
      original.insertAdjacentElement("afterend", host);
    }
    if (!original.hasAttribute("data-workflow-hidden")) {
      original.dataset.workflowDisplay = original.style.display;
      original.dataset.workflowHidden = "true";
    }
    original.style.display = "none";
    return host;
  }

  function restorePage() {
    disposeApprovals?.();
    disposeApprovals = null;
    clearTimeout(usersRefreshTimer);
    document.getElementById("workflow-page-host")?.remove();
    document.querySelectorAll("[data-workflow-hidden]").forEach((original) => {
      original.style.display = original.dataset.workflowDisplay || "";
      delete original.dataset.workflowDisplay;
      delete original.dataset.workflowHidden;
    });
  }

  async function renderApproved() {
    disposeApprovals?.();
    const main = pageHost();
    if (!main) return;
    main.dataset.workflowPage = "approved";
    main.dataset.approvalSearch = location.search;
    try {
      const {mountApprovals} = await import(window.panelUrl(`/approval-center.mjs?v=${encodeURIComponent(releaseVersion)}`));
      if (main.isConnected && window.panelRoute() === '/approved') disposeApprovals = mountApprovals(main, {api, me, dialogShell, previewDocument, openConfig, notice});
    } catch (error) {
      main.innerHTML = `<h1>Согласование</h1><p class="workflow-error" role="alert">${escapeHtml(error.message)}. Обновите страницу.</p>`;
    }
  }

  function userViewSignature(users) {
    return JSON.stringify(users.map((user) => {
      const fields = ['id', 'fullName', 'email', 'createdAt', 'company', 'department', 'departmentId', 'isManagement', 'hasRdp', 'approval', 'approvalId', 'reviewedByName', 'reviewedBy', 'documents', 'accessUntil', 'requestedAccessUntil', 'online', 'suspended', 'blockReason', 'renewal', 'configName', 'blocked', 'isActive', 'status', 'vpnEnabled'];
      const view = Object.fromEntries(fields.map((field) => [field, user[field]]));
      view.vpnIp = user.vpnIp;
      view.activated = Boolean(user.activated || user.handshakeAt);
      const until = user.accessUntil;
      view.expired = Boolean(until && new Date(/(?:Z|[+-]\d\d:\d\d)$/.test(until) ? until : `${until}Z`).getTime() <= Date.now());
      return view;
    }));
  }

  async function renderUsersPage() {
    const { creationDateLabel } = await import(window.panelUrl(`/creation-date.mjs?v=${encodeURIComponent(releaseVersion)}`));
    const { vpnCountdown } = await import(window.panelUrl(`/vpn-countdown.mjs?v=${encodeURIComponent(releaseVersion)}`));
    const { matchesEmployee } = await import(window.panelUrl(`/name-search.mjs?v=${encodeURIComponent(releaseVersion)}`));
    const { employeeVpnState } = await import(window.panelUrl(`/employee-vpn-state.mjs?v=${encodeURIComponent(releaseVersion)}`));
    clearTimeout(countdownTimer);
    clearTimeout(usersRefreshTimer);
    const main = pageHost();
    if (!main) return;
    const searchHadFocus = document.activeElement?.matches('[data-users-search]');
    const searchSelection = searchHadFocus ? [document.activeElement.selectionStart, document.activeElement.selectionEnd] : null;
    main.dataset.workflowPage = "users";
    main.innerHTML = `
      <div class="workflow-page">
        <div class="workflow-page-head"><div><p class="workflow-eyebrow">Каталог</p><h1>Пользователи</h1></div><button type="button" class="workflow-secondary" data-manual>Создать VPN вручную</button></div>
        <p class="workflow-muted">Выберите сотрудника, укажите срок и приложите служебную записку PDF. Решение и выдача ключа выполняются только в разделе «Согласование».</p>
        <div class="workflow-tabs" role="group" aria-label="Категория пользователей"><button type="button" data-users-category="all" aria-pressed="true">Все пользователи</button><button type="button" data-users-category="management" aria-pressed="false">Руководство</button></div>
        <div class="workflow-users-filters">
          <div class="workflow-users-search">
            <label for="workflow-users-search">Поиск сотрудников по ФИО или IP</label>
            <div class="workflow-users-search-field"><input id="workflow-users-search" data-users-search type="search" value="${escapeHtml(usersSearch)}" placeholder="ФИО или VPN IP, например 10.10.0.5" autocomplete="off" aria-controls="workflow-users-content" /><button type="button" class="workflow-secondary" data-users-search-clear aria-label="Очистить поиск сотрудников" ${usersSearch ? '' : 'hidden'}>Очистить</button></div>
          </div>
          <label class="workflow-department-filter">Отдел<select data-users-department><option value="">Все отделы</option></select></label>
        </div>
        <p class="workflow-muted workflow-users-search-summary" data-users-search-summary role="status"></p>
        <div id="workflow-users-content" aria-live="polite"><p class="workflow-muted">Загрузка…</p></div>
      </div>`;
    main.querySelector("[data-manual]").addEventListener("click", openManualRequest);
    const content = main.querySelector("#workflow-users-content");
    const searchInput = main.querySelector('[data-users-search]');
    const clearSearch = main.querySelector('[data-users-search-clear]');
    let renderCurrentUsers = () => {};
    searchInput.addEventListener('input', () => {
      usersSearch = searchInput.value;
      clearSearch.hidden = !usersSearch;
      renderCurrentUsers();
    });
    clearSearch.addEventListener('click', () => {
      usersSearch = '';
      searchInput.value = '';
      clearSearch.hidden = true;
      renderCurrentUsers();
      searchInput.focus({ preventScroll: true });
    });
    if (searchHadFocus) {
      searchInput.focus({ preventScroll: true });
      searchInput.setSelectionRange(...searchSelection);
    }
    try {
      const result = await api("/api/users?pageSize=500");
      if (!content.isConnected || window.panelRoute() !== '/users') return;
      let allUsers = (result.data || []).filter((user) => user.role === "USER" && user.blockReason !== 'Нет в папке Active Directory');
      let renderedSignature = userViewSignature(allUsers);
      const render = () => {
        main.querySelectorAll('[data-users-category]').forEach(button => {
          const selected = button.dataset.usersCategory === usersCategory;
          button.setAttribute('aria-pressed', String(selected));
          button.classList.toggle('active', selected);
        });
        const departmentSelect = main.querySelector('[data-users-department]');
        const departments = new Map(allUsers.filter(user => user.department).map(user => [user.departmentId || user.department, [user.company, user.department].filter(Boolean).join(' · ')]));
        if (usersDepartment && !departments.has(usersDepartment)) usersDepartment = '';
        const options = '<option value="">Все отделы</option>' + [...departments].sort((a, b) => a[1].localeCompare(b[1], 'ru')).map(([id, name]) => `<option value="${escapeHtml(id)}">${escapeHtml(name)}</option>`).join('');
        if (departmentSelect.innerHTML !== options) departmentSelect.innerHTML = options;
        departmentSelect.value = usersDepartment;
        const target = main.querySelector('#workflow-users-content');
        const content = document.createElement('div');
        const scrollPositions = [...target.querySelectorAll('.workflow-table-wrap')].map(el => el.scrollLeft);
        const focused = target.contains(document.activeElement) ? document.activeElement : null;
        const focusedRow = focused?.closest('tr')?.dataset.userId;
        const focusedData = focused ? JSON.stringify({...focused.dataset}) : null;
        const pageTop = main.scrollTop;
        const users = allUsers.filter(user => (usersCategory !== 'management' || user.isManagement) && (!usersDepartment || (user.departmentId || user.department) === usersDepartment) && matchesEmployee(user, usersSearch));
        main.querySelector('[data-users-search-summary]').textContent = `Показано сотрудников: ${users.length} из ${allUsers.length}`;
        const searching = Boolean(usersSearch.trim());
        const unapproved = users.filter((user) => user.approval !== "ISSUED");
        const allApproved = users.filter((user) => user.approval === "ISSUED");
        const working = allApproved.filter(user => !employeeVpnState(user).blocked);
        const blocked = allApproved.filter(user => employeeVpnState(user).blocked);
        const approved = usersVpnFilter === 'working' ? working : usersVpnFilter === 'blocked' ? blocked : allApproved;
        const unapprovedRows = unapproved.map((user) => {
          const pending = user.approval === "PENDING_APPROVAL" || user.approval === "APPROVED_SB";
          const state = pending ? "Ожидает согласования" : user.approval === "REJECTED" ? "Отклонено" : "Не подавалось";
          const documents = (user.documents || []).map((doc) => `<button type="button" class="workflow-link" data-document="${escapeHtml(doc.id)}" data-filename="${escapeHtml(doc.filename)}">${escapeHtml(doc.title || doc.filename)}</button>`).join(" ");
          const review = pending && user.approvalId
            ? `<a class="workflow-secondary compact" href="${escapeHtml(window.panelUrl(`/approved?status=${user.approval === 'APPROVED_SB' ? 'approved' : 'pending'}&focus=request:${encodeURIComponent(user.approvalId)}`))}">В Согласование</a>` : "";
          const status = pending ? '<span class="workflow-approval-clock" role="img" aria-label="Ожидает согласования" title="Ожидает согласования"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 12h4"/><path class="workflow-clock-hand" d="M12 12V6"/><circle cx="12" cy="12" r="1" fill="currentColor" stroke="none"/></svg></span>' : `<span class="workflow-status ${user.approval === "REJECTED" ? "rejected" : "neutral"}">${state}</span>`;
          const actions = pending ? `<span class="workflow-approval-wait">Ожидает согласования</span>${review ? `<div class="workflow-review-action">${review}</div>` : ""}` : `<button type="button" class="workflow-primary compact" data-request-user="${escapeHtml(user.id)}">Подать на согласование</button>`;
          return `<tr><td><strong>${escapeHtml(user.fullName)}</strong><small>${escapeHtml(user.email)}</small></td><td>${escapeHtml(user.company || "—")}</td><td>${escapeHtml(user.department || "—")}</td><td>${status}</td><td>${actions}${documents}</td></tr>`;
        }).join("");
        const approvedRows = approved.map((user) => {
          const activated = Boolean(user.activated || user.handshakeAt);
          const vpnState = employeeVpnState(user);
          const connection = vpnState.blocked ? `<span class="workflow-status rejected">Заблокирован</span><small data-block-reason>Причина: ${escapeHtml(vpnState.reason)}</small>` : `<span class="workflow-status ${user.online ? "online" : "neutral"}">${user.online ? "Подключён сейчас" : "Не в сети"}</span>`;
          return `<tr><td><strong>${escapeHtml(user.fullName)}</strong><small>${escapeHtml(user.email)}</small></td><td>${escapeHtml(user.company || "—")}</td><td>${escapeHtml(user.department || "—")}</td><td><span class="workflow-status approval-confirmed">Согласовано</span></td><td><span class="workflow-status ${activated ? "activated" : "not-activated"}">${activated ? "Активирован" : "Не активирован"}</span></td><td>${connection}</td><td><button type="button" class="workflow-secondary compact" data-user-key="${escapeHtml(user.id)}">Открыть ключ</button></td></tr>`;
        }).join("");
        content.innerHTML = `
          <section class="workflow-section"><div class="workflow-section-head"><h2>Не согласованные пользователи</h2><span>${unapproved.length}</span></div>${unapproved.length ? `<div class="workflow-table-wrap"><table class="workflow-table users"><thead><tr><th>ФИО</th><th>Компания</th><th>Отдел</th><th>Статус</th><th>Действие</th></tr></thead><tbody>${unapprovedRows}</tbody></table></div>` : `<div class="workflow-empty"><p>${searching ? 'По вашему запросу несогласованные сотрудники не найдены. Измените ФИО или фильтры.' : 'Несогласованных пользователей нет'}</p></div>`}</section>
          <section class="workflow-section"><div class="workflow-section-head"><h2>Согласованные пользователи</h2><span>${allApproved.length}</span></div><div class="workflow-tabs" role="group" aria-label="Состояние VPN сотрудников">${[['all','Все',allApproved.length],['working','Рабочие',working.length],['blocked','Заблокированные',blocked.length]].map(([value,label,count]) => `<button type="button" data-users-vpn="${value}" aria-label="${label}" aria-pressed="${usersVpnFilter === value}" class="${usersVpnFilter === value ? 'active' : ''}">${label} <span>${count}</span></button>`).join('')}</div>${approved.length ? `<div class="workflow-table-wrap"><table class="workflow-table users"><thead><tr><th>ФИО</th><th>Компания</th><th>Отдел</th><th>Согласование</th><th>Активация</th><th>Подключение</th><th>VPN</th></tr></thead><tbody>${approvedRows}</tbody></table></div>` : `<div class="workflow-empty"><p>${searching ? 'По вашему запросу согласованные сотрудники не найдены. Измените ФИО или фильтры.' : usersVpnFilter === 'blocked' ? 'Заблокированных сотрудников нет' : usersVpnFilter === 'working' ? 'Рабочих VPN-профилей нет' : 'Согласованных пользователей нет'}</p></div>`}</section>`;
        content.querySelectorAll('[data-users-vpn]').forEach(button => button.addEventListener('click', () => { usersVpnFilter = button.dataset.usersVpn; render(); }));
        content.querySelectorAll("[data-request-user]").forEach((button) => button.addEventListener("click", () => openEmployeeRequest(button.dataset.requestUser)));
        const approvedHeader = content.querySelector('.workflow-section:nth-child(2) thead tr');
        if (approvedHeader) {
          const authorHeader = document.createElement('th');
          authorHeader.textContent = 'Согласовал';
          approvedHeader.insertBefore(authorHeader, approvedHeader.children[4]);
          content.querySelectorAll('.workflow-section:nth-child(2) tbody tr').forEach((row, index) => {
            const author = document.createElement('td');
            author.textContent = approved[index].reviewedByName || approved[index].reviewedBy || '—';
            row.insertBefore(author, row.children[4]);
          });
        }
        if (approvedHeader) {
          const ipHeader = document.createElement('th');
          ipHeader.scope = 'col';
          ipHeader.className = 'workflow-vpn-ip';
          ipHeader.textContent = 'VPN IP';
          approvedHeader.insertBefore(ipHeader, approvedHeader.lastElementChild);
          content.querySelectorAll('.workflow-section:nth-child(2) tbody tr').forEach((row, index) => {
            const ipCell = document.createElement('td');
            ipCell.className = 'workflow-vpn-ip';
            ipCell.dataset.vpnIp = approved[index].vpnIp || '';
            ipCell.textContent = approved[index].vpnIp || '—';
            row.insertBefore(ipCell, row.lastElementChild);
          });
          const heading = document.createElement('th');
          heading.scope = 'col';
          heading.textContent = 'VPN действует до';
          heading.className = 'workflow-vpn-deadline';
          approvedHeader.insertBefore(heading, approvedHeader.lastElementChild);
        }
        content.querySelectorAll("tbody tr").forEach((row, index) => {
          const user = [...unapproved, ...approved][index];
          if (!user) return;
          row.dataset.userId = user.id;
          if (user.isManagement) {
            const badge = document.createElement('small');
            badge.className = 'workflow-management-label';
            badge.textContent = 'Руководство';
            row.children[0].appendChild(badge);
          }
          if (me.role === 'ADMIN') {
            const toggle = document.createElement('button');
            toggle.type = 'button';
            toggle.className = 'workflow-link';
            toggle.dataset.managementUser = user.id;
            toggle.textContent = user.isManagement ? 'Убрать из руководства' : 'В руководство';
            toggle.addEventListener('click', async () => {
              toggle.disabled = true;
              try {
                const updated = await api(`/api/users/${encodeURIComponent(user.id)}`, { method: 'PATCH', body: JSON.stringify({ isManagement: !user.isManagement }) });
                allUsers = allUsers.map(item => item.id === updated.id ? { ...item, ...updated } : item);
                renderedSignature = userViewSignature(allUsers);
                render();
                notice(updated.isManagement ? 'Сотрудник добавлен в руководство' : 'Сотрудник убран из руководства');
              } catch (error) {
                toggle.disabled = false;
                notice(error.message, 'error');
              }
            });
            row.children[0].appendChild(toggle);
          }
          if (user.approval === 'ISSUED') {
            const cell = document.createElement('td');
            cell.dataset.vpnDeadline = user.id;
            cell.className = 'workflow-vpn-deadline';
            const value = document.createElement('strong');
            value.dataset.vpnCountdown = user.accessUntil || '';
            value.setAttribute('role', 'timer');
            value.style.fontVariantNumeric = 'tabular-nums';
            value.textContent = vpnCountdown(user.accessUntil);
            cell.appendChild(value);
            const exactDate = document.createElement('small');
            exactDate.textContent = termLabel(user.accessUntil);
            cell.appendChild(exactDate);
            row.insertBefore(cell, row.lastElementChild);
            return;
          }
          const label = document.createElement("small");
          label.textContent = termLabel(user.accessUntil || user.requestedAccessUntil);
          row.children[0].appendChild(label);
        });
        content.querySelectorAll("[data-document]").forEach((button) => button.addEventListener("click", () => previewDocument(button.dataset.document, button.dataset.filename)));
        content.querySelectorAll("[data-user-key]").forEach((button) => {
          const user = approved.find((item) => item.id === button.dataset.userKey);
          const renewal = document.createElement('button');
          renewal.type = 'button';
          renewal.className = 'workflow-secondary compact';
          renewal.dataset.renewVpn = user.id;
          const pendingRenewal = user.renewal?.status === 'PENDING';
          renewal.textContent = pendingRenewal ? 'Продление в Согласовании' : 'Продлить VPN';
          renewal.onclick = () => pendingRenewal ? location.assign(window.panelUrl(`/approved?status=pending&focus=renewal:${encodeURIComponent(user.renewal.id)}`)) : openRenewal(user);
          button.parentElement.append(' ', renewal);
          if (user.renewal?.status === 'REJECTED') {
            const rejected = document.createElement('small');
            rejected.textContent = 'Продление отклонено';
            button.parentElement.append(rejected);
          }
          button.addEventListener("click", () => openConfig({ userId: user.id, siteId: "", subjectName: user.fullName }));
          for (const action of ["download", "copy"]) {
            const control = document.createElement("button");
            control.type = "button";
            control.className = "workflow-secondary compact";
            control.dataset.keyAction = action;
            control.textContent = action === "download" ? "Скачать" : "Копировать";
            control.addEventListener("click", async () => {
              control.disabled = true;
              try {
                if (action === "copy") {
                  const vpn = await api(`/api/users/${encodeURIComponent(user.id)}/vpn`);
                  await copyConfig(vpn.config);
                  await api("/api/audit/key-copy", { method: "POST", body: JSON.stringify({ userId: user.id, action: "copy" }) });
                  notice("Конфигурация скопирована");
                } else {
                  const blob = await api(`/api/users/${encodeURIComponent(user.id)}/wireguard.conf`);
                  const url = URL.createObjectURL(blob);
                  const link = document.createElement("a");
                  link.href = url;
                  link.download = user.configName || "wireguard.conf";
                  document.body.appendChild(link);
                  link.click();
                  link.remove();
                  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
                }
              } catch (error) { notice(error.message, "error"); }
              finally { control.disabled = false; }
            });
            button.parentElement.append(" ", control);
          }
          if (user.hasRdp) {
            const rdp = document.createElement('button');
            rdp.type = 'button'; rdp.className = 'workflow-secondary compact'; rdp.textContent = 'Скачать RDP';
            rdp.addEventListener('click', async () => {
              rdp.disabled = true;
              try {
                const blob = await api(`/api/users/${encodeURIComponent(user.id)}/remote.rdp`);
                const link = document.createElement('a'); const url = URL.createObjectURL(blob);
                link.href = url; link.download = `${user.fullName || 'remote'}.rdp`; link.click(); URL.revokeObjectURL(url);
              } catch (error) { notice(error.message, 'error'); } finally { rdp.disabled = false; }
            });
            button.parentElement.append(' ', rdp);
          }
          const exe = document.createElement('button');
          exe.type = 'button'; exe.className = 'workflow-primary compact'; exe.textContent = 'Скачать EXE';
          exe.title = 'Скачать установщик WireGuard с конфигурацией сотрудника';
          exe.addEventListener('click', async () => {
            const dialog = dialogShell('Данные доступа сотрудника');
            const body = dialog.querySelector('.workflow-dialog-body');
            body.innerHTML = `<p><strong>${escapeHtml(user.fullName)}</strong></p><p class="workflow-help">VPN-конфигурация будет автоматически взята из профиля сотрудника.</p><form class="workflow-form"><label style="display:flex;align-items:center;gap:10px"><input name="enableRdp" type="checkbox" checked style="width:auto" /> Установить RDP-подключение</label><div data-rdp-fields><label>IP-адрес рабочего компьютера *<input name="rdpHost" required placeholder="например, 192.168.1.25" /></label><label>Логин RDP *<input name="rdpUser" autocomplete="username" required placeholder="например, COMPANY\\ivanov.i" /></label><label>Пароль RDP<input name="rdpPassword" type="password" autocomplete="new-password" placeholder="Можно оставить пустым" /></label></div><p role="alert" data-exe-error></p><div class="workflow-form-actions"><button type="button" class="workflow-secondary" data-cancel>Отмена</button><button type="submit" class="workflow-primary">Сформировать EXE</button></div></form>`;
            body.querySelector('[data-cancel]').onclick = () => dialog.close();
            body.querySelector('[name="enableRdp"]').onchange = (event) => { body.querySelector('[data-rdp-fields]').hidden = !event.target.checked; body.querySelectorAll('[data-rdp-fields] input').forEach((input) => { input.required = event.target.checked && input.name !== 'rdpPassword'; }); };
            body.querySelector('form').addEventListener('submit', async (event) => {
              event.preventDefault();
              const submit = body.querySelector('button[type="submit"]');
              const error = body.querySelector('[data-exe-error]');
              submit.disabled = true; error.textContent = '';
              try {
                const enabled = body.querySelector('[name="enableRdp"]').checked;
                const payload = { rdp_host: body.querySelector('[name="rdpHost"]').value.trim(), rdp_user: body.querySelector('[name="rdpUser"]').value.trim(), rdp_password: body.querySelector('[name="rdpPassword"]').value, enable_rdp: enabled };
                const blob = await api(`/api/users/${encodeURIComponent(user.id)}/access.exe`, { method: 'POST', body: JSON.stringify(payload) });
                const link = document.createElement('a'); const url = URL.createObjectURL(blob);
                link.href = url; link.download = `${user.fullName || 'access'}_Access.exe`; link.click(); URL.revokeObjectURL(url);
                dialog.close(); notice('EXE-файл сформирован');
              } catch (err) { error.textContent = err.message; submit.disabled = false; }
            });
            dialog.showModal();
            body.querySelector('input[name="rdpHost"]').focus();
          });
          button.parentElement.append(' ', exe);
          if (APPROVERS.has(me.role)) {
            const edit = document.createElement('button');
            edit.type = 'button'; edit.className = 'workflow-secondary compact';
            edit.textContent = 'Редактировать'; edit.dataset.manageVpn = 'edit';
            edit.onclick = () => openVpnSettings(user);
            button.parentElement.append(' ', edit);
          }
          if (OPERATORS.has(me.role) && (!user.suspended || (APPROVERS.has(me.role) && user.blockReason === 'Работа приостановлена'))) {
            const pause = document.createElement('button');
            pause.type = 'button'; pause.className = 'workflow-secondary compact';
            pause.textContent = user.suspended ? 'Возобновить' : 'Приостановить';
            pause.dataset.manageVpn = 'pause';
            pause.onclick = () => openVpnPause(user);
            button.parentElement.append(' ', pause);
          }
          if (OPERATORS.has(me.role)) {
            for (const action of (APPROVERS.has(me.role) ? ["suspend", "delete"] : ["suspend"])) {
              const control = document.createElement("button");
              control.type = "button";
              control.className = "workflow-secondary compact";
              control.style.color = "#b42318";
              control.dataset.manageVpn = action;
              control.textContent = action === "delete" ? "Удалить" : user.suspended ? "VPN отключён" : "Отключить VPN";
              control.disabled = action === "suspend" && Boolean(user.suspended);
              control.addEventListener("click", () => {
                const removing = action === "delete";
                const dialog = dialogShell(removing ? "Удалить сотрудника?" : "Отключить VPN?");
                const body = dialog.querySelector(".workflow-dialog-body");
                body.innerHTML = `<p><strong>${escapeHtml(user.fullName)}</strong></p><p>${removing ? "Сотрудник и его VPN-профиль будут удалены. Доступ по ключу прекратится. Это действие нельзя отменить." : "VPN-доступ сотрудника будет приостановлен. Учётная запись останется в системе."}</p><p role="alert" data-error></p><div class="workflow-form-actions"><button type="button" class="workflow-secondary" data-cancel>Отмена</button><button type="button" class="workflow-primary" style="background:#b42318" data-confirm>${removing ? "Удалить сотрудника" : "Отключить VPN"}</button></div>`;
                body.querySelector("[data-cancel]").addEventListener("click", () => dialog.close());
                body.querySelector("[data-cancel]").focus();
                body.querySelector("[data-confirm]").addEventListener("click", async (event) => {
                  const submit = event.currentTarget;
                  submit.disabled = true;
                  try {
                    await api(`/api/users/${encodeURIComponent(user.id)}${removing ? "" : "/suspend"}`, { method: removing ? "DELETE" : "POST" });
                    dialog.close();
                    notice(removing ? "Сотрудник удалён" : "VPN отключён");
                    if (window.panelRoute() === "/users") await renderUsersPage();
                  } catch (error) {
                    body.querySelector("[data-error]").textContent = error.message;
                    submit.disabled = false;
                  }
                });
              });
              button.parentElement.append(" ", control);
            }
          }
        });
        content.querySelectorAll('.workflow-section table').forEach((table) => {
          const heading = document.createElement('th');
          heading.scope = 'col'; heading.textContent = 'Дата создания';
          table.tHead.rows[0].insertBefore(heading, table.tHead.rows[0].lastElementChild);
          table.querySelectorAll('tbody tr').forEach((row) => {
            const user = users.find(item => item.id === row.dataset.userId);
            const cell = document.createElement('td');
            cell.textContent = creationDateLabel(user?.createdAt);
            row.insertBefore(cell, row.lastElementChild);
          });
        });
        content.querySelectorAll('[data-user-key]').forEach((key) => {
          const cell = key.parentElement;
          const actions = document.createElement('div');
          actions.className = 'vpn-action-grid';
          actions.setAttribute('role', 'group');
          actions.setAttribute('aria-label', 'Действия с VPN');
          while (cell.firstChild) actions.appendChild(cell.firstChild);
          const more = document.createElement('details');
          more.className = 'vpn-more-actions';
          const summary = document.createElement('summary');
          summary.textContent = 'Ещё действия';
          more.appendChild(summary);
          const extra = document.createElement('div');
          extra.className = 'vpn-action-grid';
          for (const control of [...actions.children]) {
            if (control.matches('button') && !control.matches('[data-user-key], [data-copy-config]') && !['Скачать', 'Копировать'].includes(control.textContent.trim())) extra.appendChild(control);
          }
          if (extra.children.length) { more.appendChild(extra); actions.appendChild(more); }
          cell.appendChild(actions);
        });
        // Reuse identical rows with their listeners, focus and clock animation intact.
        for (const row of content.querySelectorAll('tbody tr')) {
          const previous = [...target.querySelectorAll('tbody tr')].find(item => item.dataset.userId === row.dataset.userId);
          if (previous && previous.outerHTML === row.outerHTML) row.replaceWith(previous);
        }
        target.replaceChildren(...content.childNodes);
        target.querySelectorAll('.workflow-table-wrap').forEach((el, index) => { el.scrollLeft = scrollPositions[index] || 0; });
        if (focusedRow && focusedData) {
          const row = [...target.querySelectorAll('tbody tr')].find(item => item.dataset.userId === focusedRow);
          const button = row && [...row.querySelectorAll('button')].find(item => JSON.stringify({...item.dataset}) === focusedData);
          button?.focus({preventScroll:true});
        }
        main.scrollTop = pageTop;
      };
      main.querySelectorAll('[data-users-category]').forEach(button => button.addEventListener('click', () => { usersCategory = button.dataset.usersCategory; render(); }));
      main.querySelector('[data-users-department]').addEventListener('change', event => { usersDepartment = event.target.value; render(); });
      renderCurrentUsers = render;
      render();
      const tickCountdown = () => {
        if (window.panelRoute() !== '/users' || !main.isConnected) return;
        main.querySelectorAll('[data-vpn-countdown]').forEach(node => {
          const next = vpnCountdown(node.dataset.vpnCountdown);
          if (node.textContent !== next) node.textContent = next;
        });
        countdownTimer = window.setTimeout(tickCountdown, 1000);
      };
      tickCountdown();
      const refresh = async () => {
        if (window.panelRoute() !== "/users" || !content.isConnected) return;
        try {
          const latest = await api("/api/users?pageSize=500");
          const updated = (latest.data || []).filter((user) => user.role === "USER" && user.blockReason !== 'Нет в папке Active Directory');
          const signature = userViewSignature(updated);
          allUsers = updated;
          if (signature !== renderedSignature) {
            renderedSignature = signature;
            if (content.isConnected) render();
          }
        } catch (_) { /* Preserve current rows while the connection recovers. */ }
        if (window.panelRoute() === "/users" && content.isConnected) usersRefreshTimer = window.setTimeout(refresh, 5000);
      };
      usersRefreshTimer = window.setTimeout(refresh, 5000);
    } catch (error) {
      content.innerHTML = `<p class="workflow-error">${escapeHtml(error.message)}</p>`;
    }
  }

  function installNav() {
    const nav = document.querySelector("nav");
    if (!nav) return;
    if (nav.hasAttribute("data-workflow-router")) return;
    nav.querySelectorAll("a[href]").forEach((item) => {
      if (window.panelRoute(new URL(item.href, location.origin).pathname) === "/requests") {
        item.hidden = true;
        item.style.display = "none";
      }
      if (item.dataset.workflowExit) return;
      item.dataset.workflowExit = "true";
      item.addEventListener("click", (event) => {
        if (window.panelRoute() !== "/approved" || item.dataset.approvedLink) return;
        event.preventDefault();
        event.stopImmediatePropagation();
        location.assign(item.href);
      }, true);
    });
    if (nav.querySelector('[data-approved-link]')) return;
    const link = document.createElement("a");
    link.href = window.panelUrl('/approved');
    link.dataset.approvedLink = "true";
    link.textContent = "Согласование";
    link.addEventListener("click", (event) => {
      event.preventDefault();
      history.pushState({}, "", window.panelUrl('/approved'));
      renderApproved();
    });
    nav.appendChild(link);
  }

  function toggleGlobalSearch(hidden) {
    const input = Array.from(document.querySelectorAll('input[placeholder]')).find((node) =>
      (node.getAttribute("placeholder") || "").includes("Поиск пользователя, IP")
    );
    if (!input) return;
    const container = input.parentElement || input;
    container.style.display = hidden ? "none" : "";
  }

  function installRequestActions() {
    if (!OPERATORS.has(me?.role) || window.panelRoute() === "/approved" || window.panelRoute() === "/users") return;
    const title = Array.from(document.querySelectorAll("h1")).find((node) => /Заявки/.test(node.textContent || ""));
    if (!title || title.parentElement?.querySelector(".workflow-request-actions")) return;
    const actions = document.createElement("div");
    actions.className = "workflow-request-actions";
    actions.innerHTML = '<button type="button" class="workflow-secondary" data-manual>Создать VPN вручную</button>';
    actions.querySelector("[data-manual]").addEventListener("click", openManualRequest);
    title.insertAdjacentElement("afterend", actions);
    if (/Заявки/.test(title.textContent || "")) {
      Array.from(document.querySelectorAll("button")).filter((button) => button.textContent?.trim() === "Новая заявка").forEach((button) => { button.hidden = true; });
    }
  }

  async function run() {
    if (!token()) return;
    try {
      if (window.panelRoute() === "/approved" && !document.querySelector("main") && !document.querySelector("nav")) {
        history.replaceState({ workflowBootstrap: true }, "", window.panelUrl('/'));
        window.dispatchEvent(new PopStateEvent("popstate"));
        window.setTimeout(() => {
          history.replaceState({}, "", window.panelUrl('/approved'));
          renderApproved();
        }, 250);
        return;
      }
      me ||= await api("/api/auth/me");
      if (!OPERATORS.has(me.role)) return;
      installNav();
      toggleGlobalSearch(window.panelRoute() === "/users");
      if (window.panelRoute() === "/users") {
        const main = document.getElementById("workflow-page-host");
        if (main?.dataset.workflowPage !== "users") await renderUsersPage();
      } else if (window.panelRoute() === "/approved") {
        const main = document.getElementById("workflow-page-host");
        if (main?.dataset.workflowPage !== "approved" || main?.dataset.approvalSearch !== location.search) await renderApproved();
      }
      else { restorePage(); installRequestActions(); }
    } catch (_) {
      // The main application handles expired sessions.
    }
  }

  function schedule() {
    clearTimeout(scheduled);
    scheduled = window.setTimeout(run, 100);
  }

  new MutationObserver(schedule).observe(document.documentElement, { childList: true, subtree: true });
  window.addEventListener('kontur:navigation', () => { clearTimeout(scheduled); run(); });
  window.addEventListener("popstate", schedule);
  document.addEventListener("click", schedule, true);
  schedule();
})();
