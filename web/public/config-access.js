(() => {
  const CARD_ID = "personal-vpn-config";
  const CONFIG_OPERATORS = new Set(["ADMIN", "IT_LEAD", "IT_STAFF"]);
  let rendering = false;

  function token() {
    return window.fortisSessionMarker?.() || '';
  }

  async function api(path) {
    const response = await fetch(path, {
      headers: {  },
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || "Не удалось загрузить конфигурацию");
    return data;
  }

  function hideForeignConfigActions(role) {
    if (CONFIG_OPERATORS.has(role) || window.panelRoute() === "/settings") return;
    document.querySelectorAll("button, a").forEach((element) => {
      const label = (element.textContent || "").trim().toLowerCase();
      if (label.includes(".conf") || label.includes("конфиг")) {
        element.style.display = "none";
      }
    });
    document.querySelectorAll(".wg-config").forEach((element) => {
      element.style.display = "none";
    });
  }

  function limitUserNavigation() {
    const nav = document.querySelector("nav");
    if (nav) {
      Array.from(nav.children).forEach((item) => { item.style.display = item.hasAttribute("data-personal-settings") ? "" : "none"; });
      if (!nav.querySelector("[data-personal-settings]")) {
        const link = document.createElement("a");
        link.href = window.panelUrl('/settings');
        link.dataset.personalSettings = "true";
        link.className = "active";
        link.textContent = "Настройки";
        nav.appendChild(link);
      }
    }
  }

  function download(filename, content) {
    const blob = new Blob([content], { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  async function render() {
    if (rendering || !token()) return;
    rendering = true;
    try {
      const me = await api("/api/auth/me");
      hideForeignConfigActions(me.role);
      if (me.role === "USER") limitUserNavigation();
      if (me.role === "USER" && window.panelRoute() !== "/settings") {
        location.replace(window.panelUrl('/settings'));
        return;
      }
      if (window.panelRoute() !== "/settings" || me.role !== "USER" || document.getElementById(CARD_ID)) return;

      const profile = await api(`/api/users/${encodeURIComponent(me.id)}`);
      const card = document.createElement("section");
      card.id = CARD_ID;
      card.className = "card wg-config";
      card.style.marginBottom = "16px";

      const title = document.createElement("h2");
      title.textContent = "Моя VPN-конфигурация";
      card.appendChild(title);

      const note = document.createElement("p");
      note.className = "muted";
      note.textContent = profile.config
        ? `Личный профиль WireGuard · VPN IP ${profile.vpnIp || "—"}`
        : "Личный VPN-профиль пока не выдан или ожидает согласования.";
      card.appendChild(note);

      if (profile.config) {
        const pre = document.createElement("pre");
        pre.className = "wg-pre";
        pre.textContent = profile.config;
        card.appendChild(pre);

        const button = document.createElement("button");
        button.type = "button";
        button.className = "btn marking";
        button.textContent = `Скачать ${profile.filename || profile.configName || "wireguard.conf"}`;
        button.addEventListener("click", () => download(profile.filename || profile.configName || "wireguard.conf", profile.config));
        card.appendChild(button);
      }

      const heading = Array.from(document.querySelectorAll("h1")).find((item) => item.textContent?.trim() === "Настройки");
      if (heading?.parentElement) {
        heading.insertAdjacentElement("afterend", card);
        Array.from(heading.parentElement.children).forEach((element) => {
          if (element !== heading && element !== card) element.style.display = "none";
        });
      }
    } catch (_) {
      // The application itself handles expired sessions and authorization errors.
    } finally {
      rendering = false;
    }
  }

  let timer = 0;
  const schedule = () => {
    window.clearTimeout(timer);
    timer = window.setTimeout(render, 80);
  };
  new MutationObserver(schedule).observe(document.documentElement, { childList: true, subtree: true });
  window.addEventListener("popstate", schedule);
  document.addEventListener("click", schedule, true);
  schedule();
})();
