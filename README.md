# GophKeeper

Клиент-серверный менеджер паролей: HTTP (Chi + templ + Swagger) и gRPC CLI.
Секреты в SQLite хранятся в AES-256-GCM. После входа JWT кладётся в HttpOnly cookie (веб) или в `~`/config (CLI).

## Запуск сервера

```bash
go run ./cmd/server
```

- веб-сейф: https://localhost:8080
- Swagger: https://localhost:8080/swagger/index.html
- скачать CLI: https://localhost:8080/downloads и `GET /api/v1/client/{windows|linux|darwin}`
- gRPC: `:9090` (TLS)

В dev ключи и самоподписанный TLS (`data/tls.crt`, `data/tls.key`) создаются автоматически.
В prod задайте `APP_ENV=prod`, `SERVER_MASTER_KEY`, `JWT_SECRET` (32 байта hex) и при необходимости `TLS_CERT_FILE`/`TLS_KEY_FILE`.

## Сборка CLI под 3 платформы

PowerShell:

```powershell
.\scripts\build-clients.ps1
```

или `make clients`. Артефакты: `bin/clients/gophkeeper-{windows,linux,darwin}-amd64`.
После сборки их отдаёт `GET /api/v1/client`.

Ручная сборка с версией (без Makefile):

```bash
go build -ldflags "-s -w -X gokeeper/pkg/version.Version=v1.0.0 -X gokeeper/pkg/version.BuildDate=2026-08-28T16:00:00Z" -o gophkeeper ./cmd/client
```

`Version` — произвольная строка (тег или `git describe`), `BuildDate` — UTC в RFC3339. Те же `-X` подходят для `./cmd/server`.

## CLI

```bash
gophkeeper version
gophkeeper register
gophkeeper login --addr localhost:9090
gophkeeper add login --url https://example.com --username u --password p
gophkeeper list
```
