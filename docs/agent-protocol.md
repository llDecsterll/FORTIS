# Агент FORTIS v2

Стандартный WireGuard остаётся режимом по умолчанию. Для агента установите `STANDARD_WIREGUARD=false` в `/etc/fortis/fortis.env`, настройте доверенный HTTPS proxy и перезапустите backend. Доступ по обычному HTTP запрещён. Для локального proxy задайте его точный адрес в `TRUSTED_PROXY_IPS`; он должен перезаписывать `X-Forwarded-Proto` и `X-Real-IP`.

## Поток регистрации

1. Администратор согласует и выдаёт заявку. В режиме агента создаётся случайный одноразовый регистрационный токен; срок — 24 часа. Передайте его пользователю защищённым способом.
2. Клиент создаёт собственную пару ключей WireGuard и вызывает `POST /api/device/register` с token, systemIdentifier, wireguardPublicKey и сведениями устройства. Сервер атомарно погашает токен, создаёт сертификат устройства и возвращает его ключ, сертификат и клиентскую конфигурацию только по HTTPS. Повторное использование, истёкшая заявка и неактивный пользователь отклоняются.
3. `POST /api/device/challenge` с certificatePem выдаёт challenge на 120 секунд, привязанный к сертификату и устройству.
4. Клиент подписывает весь запрос verify закрытым ключом сертификата. `POST /api/device/verify` проверяет подпись, привязку, срок и однократность challenge **до изменения состояния устройства**. После успешной проверки сервер выдаёт session_token и открывает peer.
5. Для каждого heartbeat нужен новый challenge и подпись. SessionToken должен принадлежать тому же устройству. При остановке heartbeat watchdog закрывает peer.

Скопированные публичный сертификат и sessionToken сами по себе не разрешают verify/heartbeat. Компрометация закрытого ключа сертификата и ключа WireGuard позволяет имитировать клиента; сведения MAC/системы не являются аппаратной аттестацией.

## Подпись

Алгоритм: RSA-PSS, SHA-256, MGF1(SHA-256), salt_length=32 (DIGEST_LENGTH). Подпись передаётся как стандартный Base64. [Документация Cryptography](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/).

Подписываются байты JSON UTF-8:

```python
json.dumps({"protocol":"fortis-agent-v2", "action":"verify", "payload":payload},
           sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
```

`payload` включает challenge и **все поля с их значениями по умолчанию**, но исключает signature. Для verify: certificatePem, systemIdentifier, mac (""), wireguardPublicKey, deviceName (""), osName (""), clientVersion ("1.0.0"), userEmail (""). Для heartbeat: challenge и sessionToken. `action` равен `verify` или `heartbeat`; подпись одного действия непригодна для другого. Повтор запроса запрещён; после сетевой ошибки получите новый challenge.

## Эталонный клиент Linux

Клиент требует Python с `cryptography` и `wireguard-tools`. Токен запрашивается скрыто, не передаётся в аргументах процесса. TLS всегда проверяется; для внутреннего HTTPS CA используйте `--ca-file /path/to/trusted-ca.pem`.

```bash
python3 tools/agent-client.py enroll --server https://vpn.example.com --state "$HOME/.fortis-client" --identity stable-device-id --name Laptop
python3 tools/agent-client.py run --server https://vpn.example.com --state "$HOME/.fortis-client"
# В другом терминале после успешной авторизации:
sudo wg-quick up "$HOME/.fortis-client/fortis.conf"
# Для отключения:
sudo wg-quick down "$HOME/.fortis-client/fortis.conf"
```

Процесс `run` должен оставаться запущенным. Файлы создаются с правами 0600, каталог 0700. При ошибке процесс прекращает heartbeat; для восстановления выполните `run` снова. Не публикуйте каталог клиента в Git и не передавайте его другим устройствам. Старые клиенты без подписи нужно обновить и зарегистрировать заново.
