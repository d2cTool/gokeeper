package httpx

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gokeeper/internal/auth"
	"gokeeper/internal/config"
	"gokeeper/internal/vault"
)

func TestWriteWebError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		err  error
		code int
		want string
	}{
		{vault.ErrNotFound, http.StatusNotFound, "item not found"},
		{vault.ErrInvalidItem, http.StatusBadRequest, "invalid item payload"},
		{vault.ErrTooLarge, http.StatusBadRequest, "binary payload exceeds 8 MiB"},
		{vault.ErrConflict, http.StatusConflict, "item version conflict"},
		{errors.New("db down"), http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError)},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		writeWebError(rec, tc.err)
		if rec.Code != tc.code {
			t.Fatalf("%v: code=%d want %d", tc.err, rec.Code, tc.code)
		}
		if body := rec.Body.String(); !strings.Contains(body, tc.want) {
			t.Fatalf("%v: body=%q want %q", tc.err, body, tc.want)
		}
	}
}

func TestWriteAuthErr(t *testing.T) {
	t.Parallel()
	cases := []struct {
		err  error
		code int
		want string
	}{
		{auth.ErrInvalidCredentials, http.StatusUnauthorized, "неверный логин или пароль"},
		{auth.ErrInvalidToken, http.StatusUnauthorized, "внутренняя ошибка сервера"},
		{auth.ErrSessionExpired, http.StatusUnauthorized, "внутренняя ошибка сервера"},
		{auth.ErrLoginTaken, http.StatusBadRequest, "логин уже занят"},
		{auth.ErrWeakPassword, http.StatusBadRequest, "пароль короче 8 символов"},
		{auth.ErrEmptyLogin, http.StatusBadRequest, "укажите логин"},
		{errors.New("sql"), http.StatusInternalServerError, "internal error"},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		writeAuthErr(rec, tc.err)
		if rec.Code != tc.code {
			t.Fatalf("%v: code=%d want %d", tc.err, rec.Code, tc.code)
		}
		var body map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body["error"] != tc.want {
			t.Fatalf("%v: error=%q want %q", tc.err, body["error"], tc.want)
		}
	}
}

func TestWriteVaultErr(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	writeVaultErr(rec, vault.ErrTooLarge)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code=%d", rec.Code)
	}
	rec = httptest.NewRecorder()
	writeVaultErr(rec, vault.ErrConflict)
	if rec.Code != http.StatusConflict {
		t.Fatalf("conflict code=%d", rec.Code)
	}
}

func TestTakeFlash(t *testing.T) {
	t.Parallel()
	cfg := config.Config{CookieSecure: false}
	rec := httptest.NewRecorder()
	setFlash(rec, cfg, "удалено")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}
	rec2 := httptest.NewRecorder()
	if got := takeFlash(rec2, req, cfg); got != "удалено" {
		t.Fatalf("flash=%q", got)
	}

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: cookieFlash, Value: "%ZZ"})
	if got := takeFlash(httptest.NewRecorder(), req, cfg); got != "%ZZ" {
		t.Fatalf("raw flash=%q", got)
	}
}

func TestHumanVaultErr(t *testing.T) {
	t.Parallel()
	if humanVaultErr(vault.ErrTooLarge) != "файл больше 8 МБ" {
		t.Fatal(humanVaultErr(vault.ErrTooLarge))
	}
	if humanVaultErr(io.EOF) != "внутренняя ошибка сервера" {
		t.Fatal(humanVaultErr(io.EOF))
	}
}
