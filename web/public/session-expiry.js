(() => {
  let redirecting = false;
  window.addEventListener('vpn:unauthorized', event => {
    const requestToken = event.detail?.token;
    // A late response from a previous session must not erase a fresh login.
    if (redirecting || typeof requestToken !== 'string' || requestToken !== (window.fortisSessionMarker?.() || '')) return;
    window.fortisClearSessionHint?.();
    for (const key of ['kontur_token', 'kontur_role', 'kontur_name', 'kontur_email']) localStorage.removeItem(key);
    if ((window.panelRoute?.() || window.location.pathname) !== '/login') {
      redirecting = true;
      window.location.replace(window.panelUrl?.('/login') || '/login');
    }
  });
})();
