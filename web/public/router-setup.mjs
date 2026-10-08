// Pure export builder. No requests, storage, key generation or server mutations.
function ipv4(value) {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(value) || value.split('.').some(x => +x > 255)) throw new Error('Мастер поддерживает только корректные IPv4-сети');
  return value.split('.').reduce((a,b) => a * 256 + +b, 0);
}
function network(value) {
  const [ip,prefix,...rest] = value.trim().split('/');
  if (rest.length || !/^\d{1,2}$/.test(prefix || '') || +prefix > 32) throw new Error('Укажите IPv4-подсеть в формате адрес/маска');
  const num=ipv4(ip), size=2 ** (32-+prefix), start=Math.floor(num/size)*size;
  const text=[24,16,8,0].map(b => Math.floor(start/2**b)%256).join('.')+'/'+ +prefix;
  return {text,start,end:start+size-1,prefix:+prefix};
}
const list = value => [...new Set((value || '').split(',').map(x=>x.trim()).filter(Boolean).map(x=>network(x).text))];
const overlaps=(a,b)=>a.start<=b.end && b.start<=a.end;

export function routerSetup(config, lanCidr, brand, iface) {
  if (!['mikrotik','keenetic'].includes(brand)) throw new Error('Выберите роутер');
  if (!(brand==='mikrotik' ? /^[a-zA-Z][a-zA-Z0-9_-]{0,19}$/ : /^Wireguard\d{1,2}$/).test(iface)) throw new Error('Недопустимое имя интерфейса');
  const sections={}; let section;
  for (const raw of config.split(/\r?\n/)) {
    const line=raw.trim(); if(!line || line.startsWith('#')) continue;
    if(line.startsWith('[')) {
      if (!['[Interface]','[Peer]'].includes(line) || sections[line]) throw new Error('Нужен один Interface и один Peer');
      section=sections[line]={}; continue;
    }
    const pos=line.indexOf('=');
    if(!section || pos<1) throw new Error('Некорректная конфигурация WireGuard');
    const name=line.slice(0,pos).trim(), value=line.slice(pos+1).trim();
    if(Object.hasOwn(section,name)) throw new Error('Повторяющийся параметр конфигурации');
    section[name]=value;
  }
  const i=sections['[Interface]'], p=sections['[Peer]'];
  if(!i || !p) throw new Error('Нужен один Interface и один Peer');
  for(const key of [i.PrivateKey,p.PublicKey,...(p.PresharedKey ? [p.PresharedKey] : [])]) {
    if(!/^[A-Za-z0-9+/]{43}=$/.test(key || '')) throw new Error('Некорректный ключ WireGuard');
  }
  network(i.Address || ''); // validate, but retain the host address, not its network
  const endpoint=p.Endpoint?.match(/^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$/);
  if(!endpoint || +endpoint[2]<1 || +endpoint[2]>65535) throw new Error('Endpoint должен содержать IPv4 и UDP-порт');
  const endpointIp=ipv4(endpoint[1]);
  const routes=list(p.AllowedIPs), lans=list(lanCidr);
  if(!routes.length) throw new Error('В конфигурации нет маршрутов AllowedIPs');
  for(const route of routes) {
    const net=network(route);
    if(endpointIp>=net.start && endpointIp<=net.end) throw new Error('Маршрут включает Endpoint сервера. Нужен отдельный маршрут к Endpoint через WAN; автоматический экспорт остановлен во избежание петли.');
    if(lans.some(lan=>overlaps(net,network(lan)))) throw new Error('Подсеть объекта пересекается с маршрутом VPN. Исправьте адресацию до настройки.');
  }
  if(lans.some(lan=>overlaps(network(lan),network(i.Address)))) throw new Error('LAN объекта пересекается с адресом туннеля');
  const keepalive=p.PersistentKeepalive || '0', mtu=i.MTU || '1420';
  if(!/^\d+$/.test(keepalive) || +keepalive>65535 || !/^\d+$/.test(mtu) || +mtu<576 || +mtu>9000) throw new Error('Некорректный MTU или keepalive');
  const warnings=[];
  if(!lans.length) warnings.push('Подсети объекта не указаны. Настройка подключит сам роутер, но доступ к оборудованию за ним требует внесения LAN объекта в систему.');
  warnings.push('Файл содержит закрытый ключ. Храните его защищённо; используйте только на одном роутере.');
  const lines=[];
  if(brand==='mikrotik') {
    lines.push(`# RouterOS 7: use an unused interface name; run once from a local session`,
      `:if ([:len [/interface find where name="${iface}"]] > 0) do={ :error "Interface already exists; stop to avoid changing an existing VPN" }`,
      `/interface wireguard add name=${iface} mtu=${mtu} private-key="${i.PrivateKey}"`,
      `/ip address add address=${i.Address} interface=${iface}`,
      `/interface wireguard peers add interface=${iface} public-key="${p.PublicKey}"${p.PresharedKey ? ` preshared-key="${p.PresharedKey}"` : ''} endpoint-address=${endpoint[1]} endpoint-port=${endpoint[2]} allowed-address=${routes.join(',')} persistent-keepalive=${keepalive}s`);
    for(const route of routes) lines.push(`/ip route add dst-address=${route} gateway=${iface} comment="vpn-setup-${iface}"`);
    for(const lan of lans) for(const route of routes) {
      // Insert before drop/FastTrack rules without disabling existing firewall rules.
      for(const [direction,src,dst] of [['out',lan,route],['in',route,lan]]) {
        lines.push(`/ip firewall filter add chain=forward action=accept ${direction==='out'?'out':'in'}-interface=${iface} src-address=${src} dst-address=${dst} comment="vpn-setup-${iface}"`);
        lines.push(`/ip firewall filter move [find where comment="vpn-setup-${iface}"] 0`);
      }
      lines.push(`/ip firewall nat add chain=srcnat action=accept out-interface=${iface} src-address=${lan} dst-address=${route} comment="vpn-setup-${iface}"`, `/ip firewall nat move [find where comment="vpn-setup-${iface}"] 0`);
    }
  } else {
    const intf=`interface ${iface}`, peer=`${intf} wireguard peer ${p.PublicKey}`;
    // Web CLI must create a peer before a subsequent request can set its properties.
    lines.push(intf,`${intf} description CorporateVPN`,`${intf} ip address ${i.Address}`,`${intf} ip mtu ${mtu}`,`${intf} security-level public`,`${intf} wireguard private-key ${i.PrivateKey}`,peer,`${peer} endpoint ${p.Endpoint}`,`${peer} keepalive-interval ${keepalive}`);
    if(p.PresharedKey) lines.push(`${peer} preshared-key ${p.PresharedKey}`);
    routes.forEach(route=>lines.push(`${peer} allow-ips ${route}`));
    lines.push(`${intf} up`);
    routes.forEach(route=>lines.push(`ip route ${route} ${iface}`));
    if(lans.length) {
      for(const route of routes) for(const lan of lans) lines.push(`access-list VPN_${iface} permit ip ${route} ${lan}`);
      lines.push(`${intf} ip access-group VPN_${iface} in`);
    }
    lines.push('system configuration save');
  }
  return {config,script:lines.join('\n')+'\n',commands:lines,routes,lans,warnings,iface,address:i.Address,endpoint:p.Endpoint,mtu,keepalive};
}

export function setupGuide(result,brand,method) {
  const {iface,routes,lans,address,endpoint,mtu,keepalive}=result;
  const common=[
    'Сохраните резервную копию настроек роутера. Выполняйте настройку из локальной сети; не через изменяемый VPN. Отключите старое использование этого же ключа на другом устройстве.',
    `Проверьте, что LAN роутера совпадает с записью объекта: ${lans.join(', ') || 'НЕ ЗАДАНА — сначала укажите её в системе'}. В мастере адреса LAN не меняются. Для соединения площадок подсети не должны пересекаться.`,
  ];
  if(brand==='mikrotik') {
    common.push('Требуется RouterOS 7 с WireGuard. В RouterOS 6 настройка не поддерживается. Проверьте версию в System → Resources.');
    if(method==='terminal') common.push(`Откройте New Terminal в WinBox/WebFig. Скачайте .rsc, загрузите в Files под именем router-setup.rsc. Убедитесь, что ${iface} ещё не существует. Выполните /import file-name=router-setup.rsc. Скрипт добавляет туннель, все маршруты и адресные правила forward/NAT; существующие правила не удаляются. Повторно не импортируйте. При ошибке остановитесь и проверьте уже добавленные строки.`);
    else common.push(
      `WireGuard → Add: Name ${iface}, MTU ${mtu}, Private Key возьмите из Interface → PrivateKey в .conf. IP → Addresses → Add: Address ${address}, Interface ${iface}.`,
      `WireGuard → Peers → Add: Interface ${iface}; Public Key и Preshared Key из секции Peer; Endpoint ${endpoint}; Persistent Keepalive ${keepalive}; Allowed Address — все сети из списка ниже. Не генерируйте другие ключи.`,
      `IP → Routes → Add: для КАЖДОЙ сети из списка задайте Dst. Address = эта сеть, Gateway = ${iface}. Всего маршрутов: ${routes.length}. Allowed Address не заменяет IP → Routes.`,
      'IP → Firewall → Filter Rules: добавьте forward/accept от LAN объекта к каждой VPN-сети (Out. Interface = туннель) и обратно (In. Interface = туннель). Ограничьте Src./Dst. Address соответствующими подсетями. Поставьте выше FastTrack/drop. NAT: srcnat/accept для LAN → VPN-сети через туннель выше masquerade. Не открывайте управление роутером из WAN. Готовые точные команды доступны при выборе «Терминал».');
    common.push(`Проверка: WireGuard → Peers — свежий handshake и рост Rx/Tx; IP → Routes — активные маршруты через ${iface}. Проверьте доступ к нужному IP и порту из LAN объекта и в обратном направлении. Для отката удалите только созданный ${iface}, его адрес, маршруты и правила с комментарием vpn-setup-${iface}, либо восстановите резервную копию.`);
  } else {
    common.push('Требуется KeeneticOS с компонентом «WireGuard VPN» (Управление → Общие настройки → Изменить набор компонентов). Команды подготовлены по справочнику KeeneticOS 4.3; перед применением на иной версии проверьте поддержку команд через «?».');
    if(method==='terminal') common.push(`Откройте Web CLI → Parse (/a) из локальной сети. Выполните show interface и убедитесь, что ${iface} не занят; при необходимости измените его номер в мастере. Копируйте полные команды строго по одной и после каждой нажимайте «Отправить запрос». Не вставляйте весь файл: поле Web CLI склеивает строки и вызывает argument parse error. При первой ошибке остановитесь. Последняя команда сохраняет результат. Не запускайте повторно на существующем интерфейсе. Для SSH/Telnet полные команды также выполняются из корневого контекста (config), не из вложенного меню.`);
    else common.push(
      'Интернет → Другие подключения → WireGuard → Загрузить из файла: выберите скачанный .conf. Проверьте адрес, Endpoint, ключи и весь список разрешённых подсетей. Запишите фактическое имя созданного интерфейса. Не включайте «Использовать для выхода в Интернет».',
      `Сетевые правила → Маршрутизация: добавьте КАЖДУЮ сеть из списка как маршрут до сети через созданное WireGuard-подключение, без другого шлюза. Всего: ${routes.length}. Проверьте существующие записи перед добавлением, чтобы не создавать дубликаты.`,
      'Сетевые правила → Межсетевой экран → созданное WireGuard-подключение: разрешите IP-трафик от каждой VPN-сети к указанным LAN объекта. Не добавляйте разрешение «от всех ко всем» и не меняйте уровень безопасности всего интерфейса на private.');
    common.push(`Проверьте, что на туннеле не включён NAT, а локальные устройства используют этот роутер как шлюз. Проверьте handshake, счётчики и доступ по IP к ресурсу из каждой нужной сети. CLI: show interface ${iface}; show ip route. Для отката отключите созданное подключение, удалите только его маршруты/правила или восстановите резервную копию.`);
  }
  common.push('Обратный доступ: на шлюзах сетей сервера должен быть маршрут к LAN объекта через VPN-сервер. Мастер не меняет внешние шлюзы. Политики доступа сервера и изоляция VPN-контуров продолжают действовать; наличие маршрута само по себе не даёт дополнительных прав. Разрешите нужные порты на конечных устройствах, не отключая их межсетевые экраны.');
  return common;
}
