package httpx

// swaggerJSON — OpenAPI 2.0 описание HTTP API, включая выдачу CLI.
var swaggerJSON = []byte(`{
  "swagger": "2.0",
  "info": {
    "title": "GophKeeper API",
    "version": "1.0.0",
    "description": "HTTP API менеджера паролей: авторизация (cookie/JWT), сейф и скачивание CLI."
  },
  "basePath": "/api/v1",
  "schemes": ["http", "https"],
  "consumes": ["application/json"],
  "produces": ["application/json"],
  "securityDefinitions": {
    "Bearer": { "type": "apiKey", "name": "Authorization", "in": "header" }
  },
  "paths": {
    "/health": { "get": { "tags": ["meta"], "summary": "Liveness", "responses": { "200": { "description": "ok" } } } },
    "/version": { "get": { "tags": ["meta"], "summary": "Версия сервера", "responses": { "200": { "description": "version" } } } },
    "/client": {
      "get": {
        "tags": ["client"],
        "summary": "Список CLI-бинарников (windows/linux/darwin)",
        "responses": { "200": { "description": "clients" } }
      }
    },
    "/client/{platform}": {
      "get": {
        "tags": ["client"],
        "summary": "Скачать CLI для платформы",
        "produces": ["application/octet-stream"],
        "parameters": [{ "name": "platform", "in": "path", "required": true, "type": "string", "enum": ["windows", "linux", "darwin"] }],
        "responses": { "200": { "description": "binary" }, "404": { "description": "not built" } }
      }
    },
    "/auth/register": {
      "post": {
        "tags": ["auth"],
        "summary": "Регистрация",
        "parameters": [{ "in": "body", "name": "body", "schema": { "$ref": "#/definitions/AuthRequest" } }],
        "responses": { "201": { "description": "tokens" }, "400": { "description": "error" } }
      }
    },
    "/auth/login": {
      "post": {
        "tags": ["auth"],
        "summary": "Вход, JWT в теле и в cookie",
        "parameters": [{ "in": "body", "name": "body", "schema": { "$ref": "#/definitions/AuthRequest" } }],
        "responses": { "200": { "description": "tokens" }, "401": { "description": "error" } }
      }
    },
    "/auth/logout": {
      "post": {
        "tags": ["auth"], "security": [{ "Bearer": [] }],
        "summary": "Выход",
        "responses": { "200": { "description": "ok" } }
      }
    },
    "/auth/refresh": {
      "post": {
        "tags": ["auth"],
        "summary": "Обновление JWT",
        "responses": { "200": { "description": "tokens" } }
      }
    },
    "/items": {
      "get": {
        "tags": ["vault"], "security": [{ "Bearer": [] }],
        "summary": "Список записей",
        "parameters": [{ "name": "type", "in": "query", "type": "string" }],
        "responses": { "200": { "description": "items" } }
      },
      "post": {
        "tags": ["vault"], "security": [{ "Bearer": [] }],
        "summary": "Создать запись",
        "responses": { "201": { "description": "item" } }
      }
    },
    "/items/{id}": {
      "get": { "tags": ["vault"], "security": [{ "Bearer": [] }], "summary": "Получить запись", "parameters": [{ "name": "id", "in": "path", "required": true, "type": "string" }], "responses": { "200": { "description": "item" } } },
      "put": { "tags": ["vault"], "security": [{ "Bearer": [] }], "summary": "Обновить запись", "parameters": [{ "name": "id", "in": "path", "required": true, "type": "string" }], "responses": { "200": { "description": "item" } } },
      "delete": { "tags": ["vault"], "security": [{ "Bearer": [] }], "summary": "Удалить запись", "parameters": [{ "name": "id", "in": "path", "required": true, "type": "string" }], "responses": { "204": { "description": "deleted" } } }
    },
    "/sync": {
      "post": {
        "tags": ["vault"], "security": [{ "Bearer": [] }],
        "summary": "LWW-синхронизация",
        "responses": { "200": { "description": "delta" } }
      }
    }
  },
  "definitions": {
    "AuthRequest": {
      "type": "object",
      "required": ["login", "password"],
      "properties": {
        "login": { "type": "string" },
        "password": { "type": "string" }
      }
    }
  }
}`)
