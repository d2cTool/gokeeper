# GophKeeper

Клиент-серверный менеджер паролей: HTTP (Chi + templ + Swagger) и gRPC CLI.
Секреты в SQLite хранятся в AES-256-GCM. После входа JWT кладётся в HttpOnly cookie (веб) или в `~`/config (CLI).

## Запуск сервера

```bash
go run ./cmd/server
```

- веб-сейф: http://localhost:8080
- Swagger: http://localhost:8080/swagger/index.html
- скачать CLI: http://localhost:8080/downloads и `GET /api/v1/client/{windows|linux|darwin}`
- gRPC: `:9090`

В dev ключи создаются в `data/`. В prod задайте `APP_ENV=prod`, `SERVER_MASTER_KEY` и `JWT_SECRET` (32 байта hex).

## Сборка CLI под 3 платформы

PowerShell:

```powershell
.\scripts\build-clients.ps1
```

или `make clients`. Артефакты: `bin/clients/gophkeeper-{windows,linux,darwin}-amd64`.
После сборки их отдаёт `GET /api/v1/client`.

## CLI

```bash
gophkeeper version
gophkeeper register
gophkeeper login --addr localhost:9090 --insecure
gophkeeper add login --url https://example.com --username u --password p
gophkeeper list
```
