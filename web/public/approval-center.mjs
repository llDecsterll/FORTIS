const escape = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const key = row => `${row.sourceType}:${row.sourceId}`;
const date = value => {
  if (!value) return 'Бессрочно';
  const normalized = /(?:Z|[+-]\d\d:\d\d)$/.test(value) ? value : `${value}Z`;
  return `${new Date(normalized).toLocaleString('ru-RU', {timeZone:'Europe/Moscow',dateStyle:'short',timeStyle:'short'})} МСК`;
};

export function mountApprovals(main, {api, me, dialogShell, previewDocument, openConfig, notice}) {
  const params = new URLSearchParams(location.search);
  let status = params.get('status') === 'approved' ? 'approved' : 'pending';
  let kind = ['employee','site','renewal'].includes(params.get('kind')) ? params.get('kind') : 'all';
  let page = 1, total = 0, stopped = false, timer, sequence = 0, signature = '', focused = false;
  const focusKey = params.get('focus');
  let locateFocus = Boolean(focusKey);
  const canApprove = ['ADMIN','IT_LEAD'].includes(me.role);
  main.innerHTML = `<div class="workflow-page approval-center">
    <div class="workflow-page-head"><div><p class="workflow-eyebrow">Управление доступом</p><h1>Согласование</h1><p>Заявки сотрудников, объектов и продления VPN — в одном месте.</p></div></div>
    <div class="workflow-tabs" role="group" aria-label="Статус согласования"><button type="button" data-approval-status="pending">Ожидают согласования</button><button type="button" data-approval-status="approved">Согласованные</button></div>
    <div class="approval-filters"><label>Тип заявки<select data-approval-kind><option value="all">Все заявки</option><option value="employee">Сотрудники</option><option value="site">Объекты</option><option value="renewal">Продления</option></select></label><p role="status" data-approval-count>Загрузка заявок…</p><button type="button" class="workflow-secondary compact" data-refresh>Обновить</button></div>
    <p class="workflow-error" role="alert" data-load-error hidden></p>
    <div data-approval-content aria-busy="true"><p role="status">Загрузка заявок…</p></div>
    <div class="approval-pagination" aria-label="Страницы заявок"><button type="button" class="workflow-secondary compact" data-prev>Назад</button><span data-page></span><button type="button" class="workflow-secondary compact" data-next>Далее</button></div>
  </div>`;
  const content = main.querySelector('[data-approval-content]');
  const error = main.querySelector('[data-load-error]');
  const refresh = main.querySelector('[data-refresh]');
  const changed = () => window.dispatchEvent(new Event('vpn:approvals-changed'));
  const alive = () => !stopped && main.isConnected && window.panelRoute() === '/approved';
  function paintFilters() {
    main.querySelectorAll('[data-approval-status]').forEach(button => {
      const selected = button.dataset.approvalStatus === status;
      button.classList.toggle('active', selected);
      button.setAttribute('aria-pressed', String(selected));
    });
    main.querySelector('[data-approval-kind]').value = kind;
    main.querySelector('[data-prev]').disabled = page <= 1;
    main.querySelector('[data-next]').disabled = page * 50 >= total;
    main.querySelector('[data-page]').textContent = `Страница ${page} из ${Math.max(1, Math.ceil(total / 50))}`;
  }
  function documentButtons(row) {
    return (row.documents || []).map(doc => `<button type="button" class="workflow-link" data-document="${escape(doc.id)}" data-filename="${escape(doc.filename)}">${escape(doc.title || doc.filename)}</button>`).join(' ') || (row.subjectKind === 'SITE' ? 'Не требуется' : '—');
  }
  function bindDocuments(root) {
    root.querySelectorAll('[data-document]').forEach(button => button.onclick = () => previewDocument(button.dataset.document, button.dataset.filename));
  }
  function review(row, issue = false) {
    const renewal = row.sourceType === 'renewal';
    const dialog = dialogShell(issue ? 'Выдать ранее согласованный VPN' : renewal ? 'Согласование продления VPN' : 'Согласование VPN');
    const body = dialog.querySelector('.workflow-dialog-body');
    body.innerHTML = `<h3>${escape(row.subjectName)}</h3><dl class="approval-details"><dt>Заявитель</dt><dd>${escape(row.createdBy || '—')}</dd>${renewal ? `<dt>Прежний срок</dt><dd>${escape(date(row.currentAccessUntil))}</dd>` : ''}<dt>${renewal ? 'Запрошенный срок' : 'Срок доступа'}</dt><dd>${escape(date(row.accessUntil))}</dd>${row.siteLanCidr ? `<dt>LAN объекта</dt><dd>${escape(row.siteLanCidr)}</dd>` : ''}<dt>Сети</dt><dd>${escape((row.networks || []).map(n => `${n.name || ''} ${n.cidr}`).join(', ') || (renewal ? 'Действующие сети сохраняются' : 'По политике доступа заявки'))}</dd></dl>
      <div>${documentButtons(row)}</div><p>${renewal ? 'Продление сохраняет существующий ключ. Приостановленный доступ автоматически не включается.' : issue ? 'Заявка уже согласована. Система создаст VPN-доступ.' : 'VPN-доступ будет выдан только после вашего подтверждения.'}</p>
      <p role="alert" data-decision-error></p><div class="workflow-form-actions"><button type="button" class="workflow-secondary" data-cancel>Отмена</button>${issue ? '' : '<button type="button" class="workflow-secondary" data-decision="reject">Отклонить</button>'}<button type="button" class="workflow-primary" data-decision="${issue ? 'issue' : 'approve'}">${issue ? 'Выдать VPN' : renewal ? 'Согласовать продление' : 'Согласовать'}</button></div>`;
    bindDocuments(body);
    body.querySelector('[data-cancel]').onclick = () => dialog.close();
    let sending = false;
    dialog.addEventListener('cancel', event => { if (sending) { event.preventDefault(); event.stopImmediatePropagation(); } }, {capture:true});
    body.querySelectorAll('[data-decision]').forEach(button => button.onclick = async () => {
      if (sending) return;
      sending = true;
      dialog.querySelectorAll('button').forEach(control => control.disabled = true);
      body.querySelector('[data-decision-error]').textContent = '';
      try {
        await api(`/api/${renewal ? 'renewals' : 'requests'}/${encodeURIComponent(row.sourceId)}/${button.dataset.decision}`, {method:'POST'});
        dialog.close();
        notice(button.dataset.decision === 'reject' ? 'Заявка отклонена' : renewal ? 'Продление согласовано' : 'VPN-доступ выдан');
        changed();
        await load();
      } catch (err) {
        body.querySelector('[data-decision-error]').textContent = `${err.message}. При потере ответа обновите список перед повторным решением.`;
      } finally {
        sending = false;
        if (dialog.isConnected) dialog.querySelectorAll('button').forEach(control => control.disabled = false);
      }
    });
  }
  async function load() {
    clearTimeout(timer);
    const requestId = ++sequence;
    const selectedStatus = status, selectedKind = kind, selectedPage = page;
    refresh.disabled = true;
    content.setAttribute('aria-busy','true');
    paintFilters();
    try {
      const query = new URLSearchParams({status, kind, page:String(page), pageSize:'50'});
      if (locateFocus && focusKey) query.set('focus', focusKey);
      const result = await api(`/api/approvals?${query}`);
      if (!alive() || requestId !== sequence) return;
      if (!Array.isArray(result.data) || !Number.isInteger(result.total)) throw new Error('Некорректный ответ списка согласований');
      total = result.total;
      if (Number.isInteger(result.page) && result.page > 0) page = result.page;
      locateFocus = false;
      if (page > 1 && !result.data.length && (page - 1) * 50 >= total) { page = Math.max(1, Math.ceil(total / 50)); return await load(); }
      error.hidden = true;
      main.querySelector('[data-approval-count]').textContent = `Заявок: ${total}`;
      const nextSignature = JSON.stringify([selectedStatus,selectedKind,selectedPage,result.data]);
      if (nextSignature !== signature) {
        signature = nextSignature;
        const activeKey = document.activeElement?.closest('[data-approval-row]')?.dataset.approvalRow;
        const oldScroll = content.querySelector('.workflow-table-wrap')?.scrollLeft || 0;
        content.innerHTML = !result.data.length ? `<div class="workflow-empty"><h2>${status === 'pending' ? 'Нет заявок, ожидающих согласования' : 'Согласованных заявок пока нет'}</h2><p>Попробуйте другой тип заявки или обновите список.</p></div>` : `<div class="workflow-table-wrap"><table class="workflow-table"><thead><tr><th>Сотрудник / объект</th><th>Тип и срок</th><th>${status === 'pending' ? 'Заявитель' : 'Согласовал'}</th><th>Служебная записка</th><th>Действие</th></tr></thead><tbody>${result.data.map(row => `<tr data-approval-row="${escape(key(row))}"><td><strong>${escape(row.subjectName || 'Запись удалена')}</strong><small>${escape([row.company,row.department].filter(Boolean).join(' · '))}</small></td><td>${row.sourceType === 'renewal' ? 'Продление VPN' : row.subjectKind === 'SITE' ? 'Объект' : 'Сотрудник'}<small>${escape(date(row.accessUntil))}</small></td><td>${escape(status === 'pending' ? row.createdBy || '—' : row.reviewedByName || row.reviewedBy || '—')}</td><td>${documentButtons(row)}</td><td>${status === 'pending' ? (canApprove ? '<button type="button" class="workflow-primary compact" data-review>Рассмотреть</button>' : '<span class="workflow-muted">Ожидает решения</span>') : row.status === 'APPROVED_SB' ? '<span>Ожидает выдачи</span><button type="button" class="workflow-primary compact" data-issue>Выдать VPN</button>' : row.sourceType === 'renewal' ? '<span class="workflow-status approval-confirmed">Продление согласовано</span>' : '<button type="button" class="workflow-secondary compact" data-config>Открыть ключ</button>'}</td></tr>`).join('')}</tbody></table></div>`;
        bindDocuments(content);
        content.querySelectorAll('[data-approval-row]').forEach(tr => {
          const row = result.data.find(item => key(item) === tr.dataset.approvalRow);
          tr.querySelector('[data-review]')?.addEventListener('click', () => review(row));
          tr.querySelector('[data-issue]')?.addEventListener('click', () => review(row, true));
          tr.querySelector('[data-config]')?.addEventListener('click', () => openConfig(row));
          if (activeKey === key(row)) tr.querySelector('button')?.focus({preventScroll:true});
          if (!focused && focusKey === key(row)) {
            focused = true; tr.tabIndex = -1; tr.classList.add('approval-highlight'); tr.focus({preventScroll:true}); tr.scrollIntoView({block:'nearest'});
          }
        });
        const scroller = content.querySelector('.workflow-table-wrap');
        if (scroller) scroller.scrollLeft = oldScroll;
      }
    } catch (err) {
      if (!alive() || requestId !== sequence) return;
      error.hidden = false;
      error.textContent = `${err.message}. Данные не обновлены. Нажмите «Обновить» или дождитесь восстановления связи.`;
      if (!signature) { content.innerHTML = ''; main.querySelector('[data-approval-count]').textContent = 'Не удалось загрузить заявки'; }
    } finally {
      if (alive() && requestId === sequence) {
        refresh.disabled = false; content.setAttribute('aria-busy','false'); paintFilters();
        timer = setTimeout(tick, 5000);
      }
    }
  }
  function tick() {
    if (!alive()) return;
    if (document.querySelector('dialog[open]')) timer = setTimeout(tick, 5000);
    else void load();
  }
  function filterChanged() {
    locateFocus = false;
    page = 1; signature = ''; content.innerHTML = '<p role="status">Загрузка заявок…</p>';
    const query = new URLSearchParams({status, kind});
    main.dataset.approvalSearch = `?${query}`;
    history.replaceState(history.state, '', window.panelUrl(`/approved?${query}`));
    void load();
  }
  main.querySelectorAll('[data-approval-status]').forEach(button => button.onclick = () => { status = button.dataset.approvalStatus; filterChanged(); });
  main.querySelector('[data-approval-kind]').onchange = event => { kind = event.target.value; filterChanged(); };
  main.querySelector('[data-prev]').onclick = () => { if (page > 1) { page--; void load(); } };
  main.querySelector('[data-next]').onclick = () => { if (page * 50 < total) { page++; void load(); } };
  refresh.onclick = () => void load();
  void load();
  return () => { stopped = true; sequence++; clearTimeout(timer); };
}
