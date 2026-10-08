# FORTIS

FORTIS — веб-панель управления корпоративным VPN на WireGuard. Она объединяет настройку сервера, учёт сотрудников и устройств, подключение роутеров и площадок, выдачу доступа к сетям и ресурсам, согласование заявок и журналирование событий.

Backend написан на Python/FastAPI, интерфейс — на React/TypeScript. VPN и правила доступа применяются на Linux через WireGuard и nftables. Для новой установки используется SQLite; PostgreSQL можно подключить через `DATABASE_URL`.

## Возможности

- Мастер первого запуска: создание администратора, обнаружение сетевых карт, настройка подключений, диагностика сервера и необязательное подключение Active Directory.
- Назначение карты: «Сотрудники», «Роутеры», собственное назначение или настройка позже. Сервер работает с одной картой; второе подключение создаётся только при наличии отдельной карты. Один адаптер нельзя использовать для двух подключений.
- Отображение системных имён, текущих IP и состояния карт. DHCP, ручная смена IP и переименование поддерживаются на Linux с Netplan; изменения подтверждаются после `netplan try`, иначе откатываются.
- Отдельные клиентские IPv4-подсети, UDP-порты и имена WireGuard-интерфейсов. Подсети подключений не должны пересекаться.
- Учётные записи, роли администратора, ИТ, безопасности, аудитора и пользователя; устройства, площадки, сети, ресурсы и согласования доступа.
- Выпуск клиентских конфигураций, управление сроками и отзывом доступа, мониторинг соединений, событий и состояния сервера.
- Необязательная интеграция с AD через LDAPS или LDAP с StartTLS и проверкой сертификата.
- 2FA для административных ролей, HttpOnly-cookie, защита CSRF и CSP. Пароли подключения к AD шифруются в хранилище.

Собственное назначение дополнительной карты создаёт подключение, но не отдельный набор бизнес-модулей: управление сотрудниками и площадками реализовано для соответствующих назначений.

## Чистая установка

Репозиторий содержит исходники, тесты и документацию. Базы, пользователи, пароли, ключи, сертификаты, загруженные документы, резервные копии, `.env`, установленные зависимости и локальное хранилище в Git не включаются. Готовых учётных записей и демонстрационных данных нет.

При первом запуске создаются новое хранилище и секрет сессий. Администратора создаёт владелец сервера в мастере. Ключи WireGuard создаются при активации выбранных подключений. Если подключить существующую БД, приложение продолжит работу с её данными — это уже не чистая установка.

## Требования к серверу

Пример ниже рассчитан на отдельный сервер Ubuntu 24.04 LTS с systemd, Python 3.12 и Netplan. Для изменения сетевых параметров нужен доступ к консоли сервера на случай потери SSH-соединения.

- Linux с поддержкой WireGuard, Python 3.10+; для инструкции используется Python 3.12.
- Node.js 22.12+ для сборки интерфейса (также поддерживается ветка 20 начиная с 20.19).
- `wireguard-tools`, `iproute2`, `nftables`, `sysctl`; права root для сетевых операций.
- Как минимум одна физическая или виртуальная Ethernet-карта и доступный клиентам UDP-порт.
- Для публикации панели: доменное имя и HTTPS на обратном прокси.

**Сетевая часть управляет firewall сервера.** Код создаёт таблицы `inet filter` и `ip nat`, заменяет одноимённые таблицы и записывает `/etc/nftables.conf`. Входящие TCP-порты разрешаются для 22, 80, 443 и 8443; UDP — для настроенных подключений. Поэтому используйте выделенный сервер, проверьте существующие правила и нестандартный SSH-порт до нажатия «Запустить сервер». Не совмещайте установку с Docker/UFW и другими владельцами этих таблиц без согласованной сетевой конфигурации.

В текущей реализации backend выполняет системные сетевые операции непосредственно. Пример службы запускает его от root; отдельный ограниченный системный помощник пока не реализован.

## Установка на свой сервер

### 1. Установите системные пакеты

```bash
sudo apt update
sudo apt install -y git curl ca-certificates xz-utils python3 python3-venv python3-dev build-essential libpq-dev wireguard-tools iproute2 nftables procps netplan.io
```

Не меняйте действующий сетевой менеджер ради установки. Netplan необходим для изменения IP/DHCP/имени из мастера; карты с другим менеджером можно использовать с текущими системными параметрами.

### 2. Установите Node.js 22

Если подходящий Node.js уже установлен системно, пропустите этот шаг. Следующий пример загружает официальный архив для x86_64 или ARM64 и проверяет SHA-256:

```bash
case "$(uname -m)" in
  x86_64) fortis_arch=x64 ;;
  aarch64|arm64) fortis_arch=arm64 ;;
  *) echo 'Установите Node.js для архитектуры сервера вручную'; exit 1 ;;
esac
fortis_node_tmp="$(mktemp -d)"
cd "$fortis_node_tmp"
curl -fsSLO https://nodejs.org/dist/latest-v22.x/SHASUMS256.txt
fortis_node_archive="$(awk -v arch="$fortis_arch" '$2 ~ ("-linux-" arch "\\.tar\\.xz$") {print $2}' SHASUMS256.txt)"
test -n "$fortis_node_archive"
curl -fsSLO "https://nodejs.org/dist/latest-v22.x/$fortis_node_archive"
awk -v file="$fortis_node_archive" '$2 == file' SHASUMS256.txt | sha256sum -c -
sudo install -d /opt/fortis-node
sudo tar -xJf "$fortis_node_archive" -C /opt/fortis-node --strip-components=1
sudo ln -sf /opt/fortis-node/bin/node /usr/local/bin/node
sudo ln -sf /opt/fortis-node/bin/npm /usr/local/bin/npm
sudo ln -sf /opt/fortis-node/bin/npx /usr/local/bin/npx
node --version
npm --version
```

Официальные загрузки: [nodejs.org](https://nodejs.org/en/download).

### 3. Получите исходники и соберите приложение

```bash
sudo git clone https://github.com/llDecsterll/FORTIS.git /opt/fortis
sudo python3 -m venv /opt/fortis/backend/.venv
sudo /opt/fortis/backend/.venv/bin/python -m pip install -r /opt/fortis/backend/requirements.txt
cd /opt/fortis/web
sudo env PATH=/usr/local/bin:/usr/bin:/bin npm ci --ignore-scripts --no-audit --no-fund
sudo env PATH=/usr/local/bin:/usr/bin:/bin npm run build
sudo install -d -m 0700 /var/lib/fortis /etc/fortis
```

Для приватного репозитория используйте авторизованный SSH/HTTPS-доступ GitHub; не записывайте токен в URL клонирования.

### 4. Настройте хранилище и службу systemd

```bash
sudo tee /etc/fortis/fortis.env >/dev/null <<'ENV'
DATA_DIR=/var/lib/fortis
DATABASE_URL=sqlite:////var/lib/fortis/fortis.db
CA_DIR=/var/lib/fortis/ca
DOCS_DIR=/var/lib/fortis/docs
UPLOADS_DIR=/var/lib/fortis/uploads
PUBLIC_ORIGIN=http://127.0.0.1:8088
ALLOWED_HOSTS=localhost,127.0.0.1,::1
ENV
sudo chmod 0600 /etc/fortis/fortis.env

sudo tee /etc/systemd/system/fortis.service >/dev/null <<'UNIT'
[Unit]
Description=FORTIS WireGuard management server
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/fortis/backend
EnvironmentFile=/etc/fortis/fortis.env
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
UMask=0077
ExecStart=/opt/fortis/backend/.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8088 --no-proxy-headers
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl daemon-reload
sudo systemctl enable --now fortis
sudo systemctl status fortis --no-pager
curl -fsS http://127.0.0.1:8088/api/setup/status
```

Служба запускает уже собранный backend; установка зависимостей и сборка при каждом перезапуске не выполняются. На свежем хранилище ответ проверки содержит `completed: false` и `adminCreated: false`.

### 5. Пройдите первый запуск

На своём компьютере откройте SSH-туннель, заменив `user@server` адресом сервера:

```bash
ssh -N -L 8088:127.0.0.1:8088 user@server
```

Откройте [http://127.0.0.1:8088](http://127.0.0.1:8088).

1. Создайте администратора: имя, email и пароль от 12 символов. Первичное создание разрешено через локальный адрес, поэтому требуется SSH-туннель.
2. Проверьте обнаруженные карты. Назначьте как минимум одну, выберите DHCP или поддерживаемые ручные настройки. Задайте имя VPN-интерфейса, частную клиентскую подсеть /8…/30, UDP-порт и адрес сервера, доступный клиентам. Остальные карты можно настроить позже.
3. Выполните диагностику и нажмите «Запустить сервер». Создаются VPN-интерфейсы, включается IPv4 forwarding и применяются правила доступа. Ручные изменения Netplan нужно подтвердить в течение окна отката.
4. Укажите AD либо пропустите шаг. После завершения войдите администратором, подключите приложение-аутентификатор и подтвердите 2FA.

При одной карте сервер создаёт только одно подключение. Для второго нужна другая карта. При нескольких картах каждая получает назначение либо остаётся для последующей настройки в «Настройки → Сетевые интерфейсы».

Токен мастера действует 30 минут и не предоставляет доступ к обычным административным API. После завершения используется отдельная сессия с 2FA.

### 6. Опубликуйте панель через HTTPS

Можно оставить панель доступной только через SSH. Для внешнего доступа сначала завершите мастер по HTTP через туннель, затем настройте HTTPS. Замените `fortis.example.ru` своим доменом и направьте его DNS-запись на сервер.

```bash
sudo apt install -y nginx certbot python3-certbot-nginx
sudo tee /etc/nginx/sites-available/fortis >/dev/null <<'NGINX'
server {
    listen 80;
    server_name fortis.example.ru;
    client_max_body_size 20m;

    location / {
        proxy_pass http://127.0.0.1:8088;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 60s;
    }
}
NGINX
sudo ln -s /etc/nginx/sites-available/fortis /etc/nginx/sites-enabled/fortis
sudo nginx -t
sudo systemctl enable --now nginx
sudo systemctl reload nginx
sudo certbot --nginx -d fortis.example.ru --redirect
sudoedit /etc/fortis/fortis.env
```

Измените в файле окружения:

```dotenv
PUBLIC_ORIGIN=https://fortis.example.ru
ALLOWED_HOSTS=localhost,127.0.0.1,::1,fortis.example.ru
```

```bash
sudo systemctl restart fortis
curl -I https://fortis.example.ru/
```

После этого cookie получают флаг Secure; входите по HTTPS. Uvicorn остаётся на loopback и не доверяет forwarded headers. Поэтому за proxy ограничения частоты используют адрес proxy, а не неподтверждённые клиентские IP.

Разрешите TCP 80/443 и выбранные UDP-порты также в облачном firewall или на внешнем роутере. При NAT настройте перенаправление UDP на нужную карту. Не открывайте порт 8088 наружу.

## Active Directory

AD можно подключить при первом запуске или позднее. LDAPS проверяет цепочку и имя сертификата; при выключенном LDAPS используется StartTLS до передачи пароля. Незащищённый LDAP и недоверенные сертификаты не принимаются.

Для корпоративного удостоверяющего центра добавьте в `/etc/fortis/fortis.env`:

```dotenv
AD_CA_FILE=/etc/fortis/company-ca.pem
```

Поместите PEM-сертификат доверенного УЦ в указанный файл и перезапустите службу. Адрес AD должен соответствовать имени в сертификате.

Пароли AD зашифрованы. Ключ хранится в `DATA_DIR/secrets/ad.key` с правами 0600. Сохраняйте резервную копию ключа отдельно от дампа БД; без исходного ключа пароли восстановить нельзя. Старые дампы с открытыми паролями автоматически не переписываются.

## Проверка работоспособности

```bash
sudo systemctl status fortis --no-pager
sudo journalctl -u fortis -n 100 --no-pager
sudo ss -lntu
sudo wg show
sudo nft list ruleset
sysctl net.ipv4.ip_forward
curl -fsS http://127.0.0.1:8088/api/setup/status
```

После настройки проверьте вход с 2FA и доступы пользователей в панели. На первом реальном клиенте импортируйте выданную конфигурацию, установите соединение, проверьте обновление handshake в `wg show` и доступ к разрешённому ресурсу. Убедитесь, что запрещённые ресурсы недоступны. Локальная проверка слушающих UDP-портов не доказывает внешнюю доступность и прохождение клиентского трафика.

При перезапуске приложение восстанавливает управляемые VPN-интерфейсы из настроек. Ошибка активации возвращает установку в незавершённое состояние; подробности смотрите в журнале.

## Данные, резервное копирование и обновление

При установке по инструкции данные находятся в `/var/lib/fortis`. При запуске `./start.sh` без окружения — в `.runtime/` в корне проекта. Каталог не включается в Git. Файлы WireGuard находятся в `/etc/wireguard/`, правила — в `/etc/nftables.d/kontur.nft`; некоторые внутренние системные пути сохраняют историческое имя `kontur`.

Храните копии БД, документов, секретов сессий, CA, ключа AD, `/etc/wireguard`, `/etc/netplan`, nftables и файла окружения в защищённом месте. Для согласованной копии SQLite остановите службу на время копирования; это окно обслуживания. Архивы содержат секреты и не предназначены для GitHub.

Настройка назначения резервных копий в панели сама по себе не создаёт расписание копирования. Автоматический backup нужно настраивать и проверять отдельно.

Обновление после резервного копирования:

```bash
sudo systemctl stop fortis
sudo git -C /opt/fortis pull --ff-only
sudo /opt/fortis/backend/.venv/bin/python -m pip install -r /opt/fortis/backend/requirements.txt
cd /opt/fortis/web
sudo env PATH=/usr/local/bin:/usr/bin:/bin npm ci --ignore-scripts --no-audit --no-fund
sudo env PATH=/usr/local/bin:/usr/bin:/bin npm run build
sudo systemctl start fortis
sudo systemctl status fortis --no-pager
```

Обновление не удаляет рабочую БД и настройки. Для новой независимой установки используйте отдельное пустое хранилище; не копируйте `.runtime` с другого сервера.

## Локальный запуск и разработка

```bash
./start.sh
```

Скрипт создаёт venv при необходимости, устанавливает Python-зависимости, собирает интерфейс и запускает панель на [http://127.0.0.1:8088](http://127.0.0.1:8088). Порт можно изменить переменной `FORTIS_PORT`.

На macOS можно проверить интерфейс и мастер, но активация Linux VPN, nftables и Netplan недоступна. Для разработки backend запускается на 8088, а интерфейс отдельно:

```bash
cd web
npm ci --ignore-scripts
npm run dev -- --host 127.0.0.1
```

Vite работает на 5173 и проксирует API на backend.

## Тесты и безопасность

```bash
cd backend
.venv/bin/python -m unittest discover -s tests -v
cd ../web
npm run build
npx tsc --noEmit
npm audit
```

Тесты используют временное хранилище, проверяют мастер, сессии, 2FA, CSRF, шифрование AD и проверку TLS. Они не заменяют испытание на целевом Linux-сервере, с настоящим AD и VPN-клиентом.

На 8 октября 2026 года: 39 backend-тестов прошли; проверки установленных Python- и npm-зависимостей не обнаружили известных уязвимостей. Результат относится к проверенным версиям и дате.

## Структура и лицензия

- `backend/app/` — API, авторизация, мастер, WireGuard, firewall и AD.
- `backend/tests/` — функциональные проверки мастера и безопасности.
- `web/src/`, `web/public/` — интерфейс и браузерные модули.
- `start.sh` — локальная установка зависимостей, сборка и запуск.

Лицензия репозитория: [GNU GPL v3](LICENSE).
