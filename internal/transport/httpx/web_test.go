package httpx_test

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"gokeeper/internal/auth"
	"gokeeper/internal/vault"
)

func webLogin(t *testing.T, h http.Handler, login string) (csrf string, jar []*http.Cookie) {
	t.Helper()
	csrf, cookies := csrfAndCookies(t, h, "/register")
	form := "csrf=" + csrf + "&login=" + url.QueryEscape(login) + "&password=supersecret"
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("register %d %s", rec.Code, rec.Body.Bytes())
	}
	jar = append(jar, rec.Result().Cookies()...)
	jar = append(jar, cookies...)
	return csrf, jar
}

func withJar(method, path, body string, jar []*http.Cookie) *http.Request {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	for _, c := range jar {
		r.AddCookie(c)
	}
	return r
}

func TestWebLoginAndRefresh(t *testing.T) {
	h := setupHTTP(t)
	body := bytes.NewBufferString(`{"login":"webauth","password":"supersecret"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("api register %d %s", rec.Code, rec.Body.Bytes())
	}

	csrf, cookies := csrfAndCookies(t, h, "/login")
	form := "csrf=" + csrf + "&login=webauth&password=supersecret"
	req = httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/vault" {
		t.Fatalf("login %d loc=%s body=%s", rec.Code, rec.Header().Get("Location"), rec.Body.Bytes())
	}
	var jar []*http.Cookie
	jar = append(jar, rec.Result().Cookies()...)
	jar = append(jar, cookies...)

	req = withJar(http.MethodGet, "/", "", jar)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/vault" {
		t.Fatalf("root auth %d loc=%s", rec.Code, rec.Header().Get("Location"))
	}

	bad := "csrf=" + csrf + "&login=webauth&password=wrongpass"
	req = withJar(http.MethodPost, "/login", bad, cookies)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || !bytes.Contains(rec.Body.Bytes(), []byte("неверный логин")) {
		t.Fatalf("bad login %d %s", rec.Code, rec.Body.Bytes())
	}

	req = httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrf})
	req.Header.Set("X-CSRF-Token", csrf)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("refresh no cookie %d loc=%s", rec.Code, rec.Header().Get("Location"))
	}

	req = httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrf})
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "bad"})
	req.Header.Set("X-CSRF-Token", csrf)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("refresh bad %d loc=%s", rec.Code, rec.Header().Get("Location"))
	}

	req = httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	for _, c := range jar {
		req.AddCookie(c)
	}
	req.Header.Set("X-CSRF-Token", csrf)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/vault" {
		t.Fatalf("refresh ok %d loc=%s", rec.Code, rec.Header().Get("Location"))
	}
}

func TestWebRegisterErrors(t *testing.T) {
	h := setupHTTP(t)
	csrf, cookies := csrfAndCookies(t, h, "/register")
	post := func(form string) *httptest.ResponseRecorder {
		t.Helper()
		req := withJar(http.MethodPost, "/register", form, cookies)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	if rec := post("csrf=" + csrf + "&login=&password=supersecret"); rec.Code != 200 || !bytes.Contains(rec.Body.Bytes(), []byte("укажите логин")) {
		t.Fatalf("empty login %d %s", rec.Code, rec.Body.Bytes())
	}
	if rec := post("csrf=" + csrf + "&login=w&password=short"); rec.Code != 200 || !bytes.Contains(rec.Body.Bytes(), []byte("пароль короче")) {
		t.Fatalf("weak %d %s", rec.Code, rec.Body.Bytes())
	}
	if rec := post("csrf=" + csrf + "&login=dup&password=supersecret"); rec.Code != http.StatusSeeOther {
		t.Fatalf("first %d %s", rec.Code, rec.Body.Bytes())
	}
	if rec := post("csrf=" + csrf + "&login=dup&password=supersecret"); rec.Code != 200 || !bytes.Contains(rec.Body.Bytes(), []byte("уже занят")) {
		t.Fatalf("taken %d %s", rec.Code, rec.Body.Bytes())
	}
}

func TestWebVaultFormTypes(t *testing.T) {
	h := setupHTTP(t)
	csrf, jar := webLogin(t, h, "formtypes")
	do := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := withJar(method, path, body, jar)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		jar = append(jar, rec.Result().Cookies()...)
		return rec
	}

	text := "csrf=" + csrf + "&type=text&title=note&body=hello&metadata=m"
	rec := do(http.MethodPost, "/vault", text)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("text create %d %s", rec.Code, rec.Body.Bytes())
	}
	textLoc := rec.Header().Get("Location")
	if rec := do(http.MethodGet, textLoc+"/edit", ""); rec.Code != 200 || !bytes.Contains(rec.Body.Bytes(), []byte("note")) {
		t.Fatalf("text edit %d %s", rec.Code, rec.Body.Bytes())
	}
	if rec := do(http.MethodPost, textLoc, "csrf="+csrf+"&title=note2&body=hello2"); rec.Code != http.StatusSeeOther {
		t.Fatalf("text update %d %s", rec.Code, rec.Body.Bytes())
	}

	card := "csrf=" + csrf + "&type=card&holder=Ann&number=4111111111111111&exp_month=12&exp_year=30&cvv=123"
	rec = do(http.MethodPost, "/vault", card)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("card create %d %s", rec.Code, rec.Body.Bytes())
	}
	cardLoc := rec.Header().Get("Location")
	if rec := do(http.MethodPost, cardLoc, "csrf="+csrf+"&holder=Bob&number=4222222222222222&exp_month=01&exp_year=31&cvv=999"); rec.Code != http.StatusSeeOther {
		t.Fatalf("card update %d %s", rec.Code, rec.Body.Bytes())
	}

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("csrf", csrf)
	_ = mw.WriteField("type", "binary")
	fw, err := mw.CreateFormFile("file", "note.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(fw, "payload"); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/vault", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	for _, c := range jar {
		req.AddCookie(c)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	jar = append(jar, rec.Result().Cookies()...)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("binary create %d %s", rec.Code, rec.Body.Bytes())
	}
	binLoc := rec.Header().Get("Location")
	if rec := do(http.MethodGet, binLoc+"/file", ""); rec.Code != 200 || rec.Body.String() != "payload" {
		t.Fatalf("file %d body=%q", rec.Code, rec.Body.String())
	}
	if rec := do(http.MethodGet, binLoc+"/edit", ""); rec.Code != 200 {
		t.Fatalf("bin edit %d", rec.Code)
	}
	if rec := do(http.MethodPost, binLoc, "csrf="+csrf+"&type=binary"); rec.Code != http.StatusSeeOther {
		t.Fatalf("binary keep file %d %s", rec.Code, rec.Body.Bytes())
	}
}

func TestWebVaultFormErrors(t *testing.T) {
	h := setupHTTP(t)
	csrf, jar := webLogin(t, h, "formerr")
	do := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := withJar(method, path, body, jar)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		jar = append(jar, rec.Result().Cookies()...)
		return rec
	}

	if rec := do(http.MethodPost, "/vault", "csrf="+csrf+"&type=login&username="); rec.Code != 200 || !bytes.Contains(rec.Body.Bytes(), []byte("обязательные")) {
		t.Fatalf("invalid create %d %s", rec.Code, rec.Body.Bytes())
	}
	if rec := do(http.MethodPost, "/vault", "csrf="+csrf+"&type=nope"); rec.Code != 200 {
		t.Fatalf("bad type %d %s", rec.Code, rec.Body.Bytes())
	}

	ok := do(http.MethodPost, "/vault", "csrf="+csrf+"&type=login&username=u&password=p")
	if ok.Code != http.StatusSeeOther {
		t.Fatalf("create %d %s", ok.Code, ok.Body.Bytes())
	}
	loc := ok.Header().Get("Location")
	if rec := do(http.MethodPost, loc, "csrf="+csrf+"&type=login&username="); rec.Code != 200 || !bytes.Contains(rec.Body.Bytes(), []byte("обязательные")) {
		t.Fatalf("invalid update %d %s", rec.Code, rec.Body.Bytes())
	}

	if rec := do(http.MethodGet, "/vault/missing-id", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("view missing %d", rec.Code)
	}
	if rec := do(http.MethodGet, "/vault/missing-id/edit", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("edit missing %d", rec.Code)
	}
	if rec := do(http.MethodGet, "/vault/missing-id/file", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("file missing %d", rec.Code)
	}
	if rec := do(http.MethodPost, "/vault/missing-id", "csrf="+csrf+"&type=login&username=u&password=p"); rec.Code != http.StatusNotFound {
		t.Fatalf("update missing %d", rec.Code)
	}
	if rec := do(http.MethodPost, "/vault/missing-id/delete", "csrf="+csrf); rec.Code != http.StatusNotFound {
		t.Fatalf("delete missing %d", rec.Code)
	}

	if rec := do(http.MethodGet, loc+"/file", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("login file %d", rec.Code)
	}

	if rec := do(http.MethodPost, loc+"/delete", "csrf="+csrf); rec.Code != http.StatusSeeOther {
		t.Fatalf("delete %d", rec.Code)
	}
	if rec := do(http.MethodGet, "/vault", ""); rec.Code != 200 || !bytes.Contains(rec.Body.Bytes(), []byte("Запись удалена")) {
		t.Fatalf("flash %d %s", rec.Code, rec.Body.Bytes())
	}
}

func TestWebVaultCreateUpdateInternalError(t *testing.T) {
	h, db := setupHTTPWithDB(t)
	csrf, jar := webLogin(t, h, "web500")
	ok := httptest.NewRecorder()
	req := withJar(http.MethodPost, "/vault", "csrf="+csrf+"&type=login&username=u&password=p", jar)
	h.ServeHTTP(ok, req)
	if ok.Code != http.StatusSeeOther {
		t.Fatalf("create %d %s", ok.Code, ok.Body.Bytes())
	}
	loc := ok.Header().Get("Location")
	if _, err := db.Exec("DROP TABLE items"); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, withJar(http.MethodPost, "/vault", "csrf="+csrf+"&type=login&username=u2&password=p", jar))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("create 500 %d %s", rec.Code, rec.Body.Bytes())
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, withJar(http.MethodPost, loc, "csrf="+csrf+"&type=login&username=u3&password=p", jar))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("update 500 %d %s", rec.Code, rec.Body.Bytes())
	}
}

func TestAPIAuthErrorMapping(t *testing.T) {
	h := setupHTTP(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewBufferString(`{`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad json %d", rec.Code)
	}

	post := func(path, raw string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(raw))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if rec := post("/api/v1/auth/register", `{"login":"","password":"supersecret"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty %d %s", rec.Code, rec.Body.Bytes())
	}
	if rec := post("/api/v1/auth/register", `{"login":"a","password":"short"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("weak %d %s", rec.Code, rec.Body.Bytes())
	}
	if rec := post("/api/v1/auth/register", `{"login":"mapu","password":"supersecret"}`); rec.Code != http.StatusCreated {
		t.Fatalf("ok %d %s", rec.Code, rec.Body.Bytes())
	}
	if rec := post("/api/v1/auth/register", `{"login":"mapu","password":"supersecret"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("taken %d %s", rec.Code, rec.Body.Bytes())
	}
	if rec := post("/api/v1/auth/login", `{"login":"mapu","password":"wrongpass"}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("creds %d %s", rec.Code, rec.Body.Bytes())
	}
	if rec := post("/api/v1/auth/login", `{`); rec.Code != http.StatusBadRequest {
		t.Fatalf("login json %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("refresh %d", rec.Code)
	}
}

func TestAPIInvalidJSONAndEmptyList(t *testing.T) {
	h := setupHTTP(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewBufferString(`{"login":"empty","password":"supersecret"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var tokens auth.Tokens
	if err := json.Unmarshal(rec.Body.Bytes(), &tokens); err != nil {
		t.Fatal(err)
	}
	authz := "Bearer " + tokens.AccessToken

	req = httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
	req.Header.Set("Authorization", authz)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || !bytes.Contains(rec.Body.Bytes(), []byte(`"items"`)) {
		t.Fatalf("empty list %d %s", rec.Code, rec.Body.Bytes())
	}

	for _, path := range []string{"/api/v1/items", "/api/v1/items/x", "/api/v1/sync"} {
		method := http.MethodPost
		if path == "/api/v1/items/x" {
			method = http.MethodPut
		}
		req = httptest.NewRequest(method, path, bytes.NewBufferString(`{`))
		req.Header.Set("Authorization", authz)
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s json %d", path, rec.Code)
		}
	}

	bin := `{"type":"binary","binary":{"filename":"a.bin","data":"YQ=="}}`
	req = httptest.NewRequest(http.MethodPost, "/api/v1/items", bytes.NewBufferString(bin))
	req.Header.Set("Authorization", authz)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("bin %d %s", rec.Code, rec.Body.Bytes())
	}
	var it vault.Item
	if err := json.Unmarshal(rec.Body.Bytes(), &it); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodGet, "/vault/"+it.ID+"/file", nil)
	req.Header.Set("Authorization", authz)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || rec.Body.String() != "a" {
		t.Fatalf("download %d %q", rec.Code, rec.Body.String())
	}
}
