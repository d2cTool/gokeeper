package httpx_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"gokeeper/internal/auth"
	"gokeeper/internal/config"
	"gokeeper/internal/cryptox"
	"gokeeper/internal/download"
	"gokeeper/internal/storage/sqlite"
	"gokeeper/internal/transport/httpx"
	"gokeeper/internal/vault"
)

func setupHTTP(t *testing.T) http.Handler {
	t.Helper()
	dir := t.TempDir()
	db, err := sqlite.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlite.Close(db) })
	master, _ := cryptox.NewSalt(32)
	jwt, _ := cryptox.NewSalt(32)
	binDir := filepath.Join(dir, "clients")
	_ = os.MkdirAll(binDir, 0o755)
	_ = os.WriteFile(filepath.Join(binDir, "gophkeeper-linux-amd64"), []byte("elf"), 0o644)
	return httpx.NewRouter(httpx.Deps{
		Cfg:      config.Config{CookieSecure: false, ClientBinDir: binDir, JWTSecret: jwt, MasterKey: master},
		Auth:     auth.NewService(db, jwt, master),
		Vault:    vault.NewService(db),
		Download: download.Catalog{Dir: binDir},
	})
}

func TestClientDownloadAPI(t *testing.T) {
	h := setupHTTP(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/client", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.Bytes())
	}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/client/linux", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || rec.Body.String() != "elf" {
		t.Fatalf("download code=%d body=%q", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Content-Disposition") == "" {
		t.Fatal("missing disposition")
	}
}

func TestRegisterLoginCookieAndItems(t *testing.T) {
	h := setupHTTP(t)
	body := bytes.NewBufferString(`{"login":"ann","password":"supersecret"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register %d %s", rec.Code, rec.Body.Bytes())
	}
	var tokens auth.Tokens
	if err := json.Unmarshal(rec.Body.Bytes(), &tokens); err != nil {
		t.Fatal(err)
	}
	if rec.Result().Cookies() == nil {
		t.Fatal("no cookies")
	}
	var gotCookie bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == "access_token" && c.HttpOnly {
			gotCookie = true
		}
	}
	if !gotCookie {
		t.Fatal("access_token cookie missing")
	}

	item := bytes.NewBufferString(`{"type":"login","login":{"url":"https://a","username":"u","password":"p"}}`)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/items", item)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create %d %s", rec.Code, rec.Body.Bytes())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || !bytes.Contains(rec.Body.Bytes(), []byte("username")) {
		t.Fatalf("list %d %s", rec.Code, rec.Body.Bytes())
	}
}

func TestAPIVaultErrorStatus(t *testing.T) {
	h := setupHTTP(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewBufferString(`{"login":"erru","password":"supersecret"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var tokens auth.Tokens
	if err := json.Unmarshal(rec.Body.Bytes(), &tokens); err != nil {
		t.Fatal(err)
	}
	authz := "Bearer " + tokens.AccessToken

	req = httptest.NewRequest(http.MethodGet, "/api/v1/items?type=nope", nil)
	req.Header.Set("Authorization", authz)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad type list %d %s", rec.Code, rec.Body.Bytes())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/items", bytes.NewBufferString(`{"type":"login"}`))
	req.Header.Set("Authorization", authz)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid create %d %s", rec.Code, rec.Body.Bytes())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/items/missing-id", nil)
	req.Header.Set("Authorization", authz)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get missing %d %s", rec.Code, rec.Body.Bytes())
	}

	req = httptest.NewRequest(http.MethodPut, "/api/v1/items/missing-id", bytes.NewBufferString(`{"type":"login","login":{"username":"u","password":"p"}}`))
	req.Header.Set("Authorization", authz)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("put missing %d %s", rec.Code, rec.Body.Bytes())
	}

	req = httptest.NewRequest(http.MethodDelete, "/api/v1/items/missing-id", nil)
	req.Header.Set("Authorization", authz)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("del missing %d %s", rec.Code, rec.Body.Bytes())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/sync", bytes.NewBufferString(`{"items":[{"id":"x","type":"login"}]}`))
	req.Header.Set("Authorization", authz)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("sync invalid %d %s", rec.Code, rec.Body.Bytes())
	}

	req = httptest.NewRequest(http.MethodGet, "/vault?type=nope", nil)
	req.Header.Set("Authorization", authz)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("web list bad type %d %s", rec.Code, rec.Body.Bytes())
	}
}

func TestAPIMapsInternalErrors(t *testing.T) {
	dir := t.TempDir()
	db, err := sqlite.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlite.Close(db) })
	master, _ := cryptox.NewSalt(32)
	jwt, _ := cryptox.NewSalt(32)
	h := httpx.NewRouter(httpx.Deps{
		Cfg:      config.Config{CookieSecure: false, JWTSecret: jwt, MasterKey: master},
		Auth:     auth.NewService(db, jwt, master),
		Vault:    vault.NewService(db),
		Download: download.Catalog{Dir: dir},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewBufferString(`{"login":"dbu","password":"supersecret"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register %d %s", rec.Code, rec.Body.Bytes())
	}
	var tokens auth.Tokens
	if err := json.Unmarshal(rec.Body.Bytes(), &tokens); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("DROP TABLE items"); err != nil {
		t.Fatal(err)
	}

	authz := "Bearer " + tokens.AccessToken
	req = httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
	req.Header.Set("Authorization", authz)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("list broken db %d %s", rec.Code, rec.Body.Bytes())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/items", bytes.NewBufferString(`{"type":"login","login":{"username":"u","password":"p"}}`))
	req.Header.Set("Authorization", authz)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("create broken db %d %s", rec.Code, rec.Body.Bytes())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/sync", bytes.NewBufferString(`{"since_version":0,"items":[]}`))
	req.Header.Set("Authorization", authz)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("sync broken db %d %s", rec.Code, rec.Body.Bytes())
	}

	req = httptest.NewRequest(http.MethodGet, "/vault", nil)
	req.Header.Set("Authorization", authz)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("web list broken db %d %s", rec.Code, rec.Body.Bytes())
	}

	if err := sqlite.Close(db); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(`{"login":"dbu","password":"supersecret"}`))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("login closed db %d %s", rec.Code, rec.Body.Bytes())
	}
}

func TestUnauthorizedAPI(t *testing.T) {
	h := setupHTTP(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code=%d", rec.Code)
	}
}

func TestLoginPageCSRF(t *testing.T) {
	h := setupHTTP(t)
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || !bytes.Contains(rec.Body.Bytes(), []byte("csrf")) {
		t.Fatalf("login page %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodPost, "/login", bytes.NewBufferString("login=a&password=bbbbbbbb"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("csrf code=%d", rec.Code)
	}
}

func TestPublicPagesAndItemLifecycle(t *testing.T) {
	h := setupHTTP(t)
	for _, path := range []string{"/", "/downloads", "/register", "/api/v1/health", "/api/v1/version", "/swagger/doc.json"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code >= 400 {
			t.Fatalf("%s -> %d", path, rec.Code)
		}
	}

	body := bytes.NewBufferString(`{"login":"kim","password":"supersecret"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var tokens auth.Tokens
	if err := json.Unmarshal(rec.Body.Bytes(), &tokens); err != nil {
		t.Fatal(err)
	}
	authz := "Bearer " + tokens.AccessToken

	create := func(raw string) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/items", bytes.NewBufferString(raw))
		req.Header.Set("Authorization", authz)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create %d %s", rec.Code, rec.Body.Bytes())
		}
		var it vault.Item
		if err := json.Unmarshal(rec.Body.Bytes(), &it); err != nil {
			t.Fatal(err)
		}
		return it.ID
	}
	id := create(`{"type":"text","text":{"title":"n","body":"b"}}`)
	req = httptest.NewRequest(http.MethodGet, "/api/v1/items/"+id, nil)
	req.Header.Set("Authorization", authz)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("get %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodPut, "/api/v1/items/"+id, bytes.NewBufferString(`{"type":"text","text":{"title":"n2","body":"b2"}}`))
	req.Header.Set("Authorization", authz)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("put %d %s", rec.Code, rec.Body.Bytes())
	}
	req = httptest.NewRequest(http.MethodPost, "/api/v1/sync", bytes.NewBufferString(`{"since_version":0,"items":[]}`))
	req.Header.Set("Authorization", authz)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("sync %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodDelete, "/api/v1/items/"+id, nil)
	req.Header.Set("Authorization", authz)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("del %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/vault", nil)
	req.Header.Set("Authorization", authz)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("vault page %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/vault", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("anon vault %d", rec.Code)
	}
}

func csrfAndCookies(t *testing.T, h http.Handler, path string) (string, []*http.Cookie) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var token string
	for _, c := range rec.Result().Cookies() {
		if c.Name == "csrf_token" {
			token = c.Value
		}
	}
	if token == "" {
		t.Fatal("no csrf")
	}
	return token, rec.Result().Cookies()
}

func TestWebRegisterLoginVaultForms(t *testing.T) {
	h := setupHTTP(t)
	csrf, cookies := csrfAndCookies(t, h, "/register")
	form := "csrf=" + csrf + "&login=webuser&password=supersecret"
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBufferString(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("register %d %s", rec.Code, rec.Body.Bytes())
	}
	var jar []*http.Cookie
	jar = append(jar, rec.Result().Cookies()...)
	jar = append(jar, cookies...)

	do := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		var r *http.Request
		if body != "" {
			r = httptest.NewRequest(method, path, bytes.NewBufferString(body))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		} else {
			r = httptest.NewRequest(method, path, nil)
		}
		for _, c := range jar {
			r.AddCookie(c)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		jar = append(jar, w.Result().Cookies()...)
		return w
	}

	if rec := do(http.MethodGet, "/vault/new", ""); rec.Code != 200 {
		t.Fatalf("new %d", rec.Code)
	}
	create := "csrf=" + csrf + "&type=login&url=https://ex&username=u&password=p&metadata=m"
	rec = do(http.MethodPost, "/vault", create)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create form %d %s", rec.Code, rec.Body.Bytes())
	}
	loc := rec.Header().Get("Location")
	if loc == "" {
		t.Fatal("no location")
	}
	if rec := do(http.MethodGet, loc, ""); rec.Code != 200 || !bytes.Contains(rec.Body.Bytes(), []byte("u")) {
		t.Fatalf("view %d %s", rec.Code, rec.Body.Bytes())
	}
	if rec := do(http.MethodGet, loc+"?reveal=1", ""); rec.Code != 200 {
		t.Fatalf("reveal %d", rec.Code)
	}
	if rec := do(http.MethodGet, loc+"/edit", ""); rec.Code != 200 {
		t.Fatalf("edit %d", rec.Code)
	}
	upd := "csrf=" + csrf + "&type=login&url=https://ex2&username=u2&password=p2"
	if rec := do(http.MethodPost, loc, upd); rec.Code != http.StatusSeeOther {
		t.Fatalf("update %d %s", rec.Code, rec.Body.Bytes())
	}
	if rec := do(http.MethodPost, loc+"/delete", "csrf="+csrf); rec.Code != http.StatusSeeOther {
		t.Fatalf("delete %d", rec.Code)
	}
	if rec := do(http.MethodPost, "/logout", "csrf="+csrf); rec.Code != http.StatusSeeOther {
		t.Fatalf("logout %d", rec.Code)
	}
}

func TestAPILoginRefreshLogout(t *testing.T) {
	h := setupHTTP(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewBufferString(`{"login":"ref","password":"supersecret"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var tokens auth.Tokens
	_ = json.Unmarshal(rec.Body.Bytes(), &tokens)

	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(`{"login":"ref","password":"supersecret"}`))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("login %d", rec.Code)
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &tokens)

	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewBufferString(`{"refresh_token":"`+tokens.RefreshToken+`"}`))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("refresh %d %s", rec.Code, rec.Body.Bytes())
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &tokens)

	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("logout %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/client/windows", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 404 {
		t.Fatalf("windows download %d", rec.Code)
	}
}
