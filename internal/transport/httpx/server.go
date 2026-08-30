package httpx

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	httpSwagger "github.com/swaggo/http-swagger"

	"gokeeper/internal/auth"
	"gokeeper/internal/config"
	"gokeeper/internal/download"
	"gokeeper/internal/vault"
	"gokeeper/internal/web"
	"gokeeper/internal/web/templates"
	"gokeeper/pkg/version"
)

// Deps — зависимости HTTP-слоя.
type Deps struct {
	Cfg      config.Config
	Auth     *auth.Service
	Vault    *vault.Service
	Download download.Catalog
}

// NewRouter собирает Chi-роутер с веб-страницами, JSON API и Swagger.
func NewRouter(d Deps) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(csrfMiddleware(d.Cfg))
	r.Use(d.optionalAuth)

	static, _ := fs.Sub(web.Static, "static")
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.FS(static))))

	r.Get("/swagger/doc.json", serveSwagger)
	r.Get("/swagger/*", httpSwagger.Handler(httpSwagger.URL("/swagger/doc.json")))

	r.Get("/", d.getRoot)
	r.Get("/login", d.getLogin)
	r.Post("/login", d.postLogin)
	r.Get("/register", d.getRegister)
	r.Post("/register", d.postRegister)
	r.Post("/logout", d.postLogout)
	r.Post("/auth/refresh", d.postRefresh)

	r.Get("/downloads", d.getDownloads)
	r.Get("/vault", d.requireWeb(d.getVault))
	r.Get("/vault/new", d.requireWeb(d.getVaultNew))
	r.Post("/vault", d.requireWeb(d.postVaultCreate))
	r.Get("/vault/{id}", d.requireWeb(d.getVaultItem))
	r.Get("/vault/{id}/edit", d.requireWeb(d.getVaultEdit))
	r.Get("/vault/{id}/file", d.requireWeb(d.getVaultFile))
	r.Post("/vault/{id}", d.requireWeb(d.postVaultUpdate))
	r.Post("/vault/{id}/delete", d.requireWeb(d.postVaultDelete))

	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/health", d.apiHealth)
		r.Get("/version", d.apiVersion)
		r.Get("/client", d.apiClientList)
		r.Get("/client/{platform}", d.apiClientDownload)
		r.Post("/auth/register", d.apiRegister)
		r.Post("/auth/login", d.apiLogin)
		r.Post("/auth/logout", d.apiLogout)
		r.Post("/auth/refresh", d.apiRefresh)

		r.Group(func(r chi.Router) {
			r.Use(d.requireAPI)
			r.Get("/items", d.apiListItems)
			r.Post("/items", d.apiCreateItem)
			r.Get("/items/{id}", d.apiGetItem)
			r.Put("/items/{id}", d.apiUpdateItem)
			r.Delete("/items/{id}", d.apiDeleteItem)
			r.Post("/sync", d.apiSync)
		})
	})
	return r
}

func (d Deps) optionalAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tok := accessTokenFromRequest(r); tok != "" {
			if p, err := d.Auth.Authenticate(r.Context(), tok); err == nil {
				r = r.WithContext(withPrincipal(r.Context(), p))
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (d Deps) requireWeb(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requestPrincipal(r); !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		h(w, r)
	}
}

func (d Deps) requireAPI(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requestPrincipal(r); !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (d Deps) page(w http.ResponseWriter, r *http.Request, title string) templates.Page {
	p := templates.Page{Title: title, CSRF: csrfFrom(r.Context()), Flash: takeFlash(w, r, d.Cfg)}
	if pr, ok := requestPrincipal(r); ok {
		p.Login = pr.Login
	}
	return p
}

func (d Deps) getRoot(w http.ResponseWriter, r *http.Request) {
	if _, ok := requestPrincipal(r); ok {
		http.Redirect(w, r, "/vault", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (d Deps) getLogin(w http.ResponseWriter, r *http.Request) {
	templates.LoginPage(d.page(w, r, "Вход"), "").Render(r.Context(), w)
}

func (d Deps) getRegister(w http.ResponseWriter, r *http.Request) {
	templates.RegisterPage(d.page(w, r, "Регистрация"), "").Render(r.Context(), w)
}

func (d Deps) postLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		templates.LoginPage(d.page(w, r, "Вход"), "некорректная форма").Render(r.Context(), w)
		return
	}
	tokens, err := d.Auth.Login(r.Context(), r.FormValue("login"), r.FormValue("password"))
	if err != nil {
		templates.LoginPage(d.page(w, r, "Вход"), humanAuthErr(err)).Render(r.Context(), w)
		return
	}
	setAuthCookies(w, d.Cfg, tokens)
	http.Redirect(w, r, "/vault", http.StatusSeeOther)
}

func (d Deps) postRegister(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		templates.RegisterPage(d.page(w, r, "Регистрация"), "некорректная форма").Render(r.Context(), w)
		return
	}
	tokens, err := d.Auth.Register(r.Context(), r.FormValue("login"), r.FormValue("password"))
	if err != nil {
		templates.RegisterPage(d.page(w, r, "Регистрация"), humanAuthErr(err)).Render(r.Context(), w)
		return
	}
	setAuthCookies(w, d.Cfg, tokens)
	http.Redirect(w, r, "/vault", http.StatusSeeOther)
}

func (d Deps) postLogout(w http.ResponseWriter, r *http.Request) {
	if p, ok := requestPrincipal(r); ok {
		_ = d.Auth.Logout(r.Context(), p.SessionID)
	}
	clearAuthCookies(w, d.Cfg)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (d Deps) postRefresh(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(cookieRefresh)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	tokens, err := d.Auth.Refresh(r.Context(), c.Value)
	if err != nil {
		clearAuthCookies(w, d.Cfg)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	setAuthCookies(w, d.Cfg, tokens)
	http.Redirect(w, r, "/vault", http.StatusSeeOther)
}

func (d Deps) getDownloads(w http.ResponseWriter, r *http.Request) {
	templates.DownloadsPage(d.page(w, r, "Клиент"), d.Download.List()).Render(r.Context(), w)
}

func (d Deps) getVault(w http.ResponseWriter, r *http.Request) {
	p, _ := requestPrincipal(r)
	typ := r.URL.Query().Get("type")
	items, err := d.Vault.List(r.Context(), p.UserID, p.KEK, typ)
	if err != nil {
		writeWebError(w, err)
		return
	}
	templates.VaultList(d.page(w, r, "Сейф"), items, typ).Render(r.Context(), w)
}

func (d Deps) getVaultNew(w http.ResponseWriter, r *http.Request) {
	templates.VaultForm(d.page(w, r, "Новая запись"), vault.Item{Type: vault.TypeLogin}, true, "").Render(r.Context(), w)
}

func (d Deps) getVaultItem(w http.ResponseWriter, r *http.Request) {
	p, _ := requestPrincipal(r)
	it, err := d.Vault.Get(r.Context(), p.UserID, p.KEK, chi.URLParam(r, "id"))
	if err != nil {
		writeWebError(w, err)
		return
	}
	show := r.URL.Query().Get("reveal") == "1"
	templates.VaultView(d.page(w, r, it.Title()), it, show).Render(r.Context(), w)
}

func (d Deps) getVaultEdit(w http.ResponseWriter, r *http.Request) {
	p, _ := requestPrincipal(r)
	it, err := d.Vault.Get(r.Context(), p.UserID, p.KEK, chi.URLParam(r, "id"))
	if err != nil {
		writeWebError(w, err)
		return
	}
	templates.VaultForm(d.page(w, r, "Редактирование"), it, false, "").Render(r.Context(), w)
}

func (d Deps) getVaultFile(w http.ResponseWriter, r *http.Request) {
	p, _ := requestPrincipal(r)
	it, err := d.Vault.GetBinary(r.Context(), p.UserID, p.KEK, chi.URLParam(r, "id"))
	if err != nil {
		writeWebError(w, err)
		return
	}
	if it.Binary == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+it.Binary.Filename+`"`)
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(it.Binary.Data)
}

func (d Deps) postVaultCreate(w http.ResponseWriter, r *http.Request) {
	p, _ := requestPrincipal(r)
	it, err := itemFromForm(r, vault.Item{}, true)
	if err != nil {
		templates.VaultForm(d.page(w, r, "Новая запись"), it, true, err.Error()).Render(r.Context(), w)
		return
	}
	created, err := d.Vault.Create(r.Context(), p.UserID, p.KEK, it)
	if err != nil {
		if vaultStatus(err) >= 500 {
			writeWebError(w, err)
			return
		}
		templates.VaultForm(d.page(w, r, "Новая запись"), it, true, humanVaultErr(err)).Render(r.Context(), w)
		return
	}
	http.Redirect(w, r, "/vault/"+created.ID, http.StatusSeeOther)
}

func (d Deps) postVaultUpdate(w http.ResponseWriter, r *http.Request) {
	p, _ := requestPrincipal(r)
	id := chi.URLParam(r, "id")
	cur, err := d.Vault.Get(r.Context(), p.UserID, p.KEK, id)
	if err != nil {
		writeWebError(w, err)
		return
	}
	it, err := itemFromForm(r, cur, false)
	if err != nil {
		templates.VaultForm(d.page(w, r, "Редактирование"), it, false, err.Error()).Render(r.Context(), w)
		return
	}
	it.ID = id
	if _, err := d.Vault.Update(r.Context(), p.UserID, p.KEK, it); err != nil {
		if vaultStatus(err) >= 500 {
			writeWebError(w, err)
			return
		}
		templates.VaultForm(d.page(w, r, "Редактирование"), it, false, humanVaultErr(err)).Render(r.Context(), w)
		return
	}
	http.Redirect(w, r, "/vault/"+id, http.StatusSeeOther)
}

func (d Deps) postVaultDelete(w http.ResponseWriter, r *http.Request) {
	p, _ := requestPrincipal(r)
	if err := d.Vault.Delete(r.Context(), p.UserID, chi.URLParam(r, "id"), "web"); err != nil {
		writeWebError(w, err)
		return
	}
	setFlash(w, d.Cfg, "Запись удалена")
	http.Redirect(w, r, "/vault", http.StatusSeeOther)
}

func itemFromForm(r *http.Request, cur vault.Item, isNew bool) (vault.Item, error) {
	if err := r.ParseMultipartForm(maxBinaryForm); err != nil {
		if err := r.ParseForm(); err != nil {
			return cur, err
		}
	}
	typ := r.FormValue("type")
	if typ == "" {
		typ = string(cur.Type)
	}
	t, err := vault.ParseType(typ)
	if err != nil {
		return cur, err
	}
	it := vault.Item{ID: cur.ID, Type: t, Metadata: r.FormValue("metadata")}
	switch t {
	case vault.TypeLogin:
		it.Login = &vault.LoginPayload{
			URL: r.FormValue("url"), Username: r.FormValue("username"), Password: r.FormValue("password"),
		}
	case vault.TypeText:
		it.Text = &vault.TextPayload{Title: r.FormValue("title"), Body: r.FormValue("body")}
	case vault.TypeCard:
		it.Card = &vault.CardPayload{
			Holder: r.FormValue("holder"), Number: r.FormValue("number"),
			ExpMonth: r.FormValue("exp_month"), ExpYear: r.FormValue("exp_year"), CVV: r.FormValue("cvv"),
		}
	case vault.TypeBinary:
		it.Binary = &vault.BinaryPayload{Filename: ""}
		if f, hdr, err := r.FormFile("file"); err == nil {
			defer f.Close()
			data, err := io.ReadAll(io.LimitReader(f, maxBinaryForm+1))
			if err != nil {
				return it, err
			}
			it.Binary = &vault.BinaryPayload{Filename: hdr.Filename, Data: data}
		} else if !isNew && cur.Binary != nil {
			it.Binary = cur.Binary
		}
	}
	return it, nil
}

const maxBinaryForm = 8 << 20

func humanAuthErr(err error) string {
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		return "неверный логин или пароль"
	case errors.Is(err, auth.ErrLoginTaken):
		return "логин уже занят"
	case errors.Is(err, auth.ErrWeakPassword):
		return "пароль короче 8 символов"
	case errors.Is(err, auth.ErrEmptyLogin):
		return "укажите логин"
	default:
		return "внутренняя ошибка сервера"
	}
}

func humanVaultErr(err error) string {
	switch {
	case errors.Is(err, vault.ErrInvalidItem):
		return "заполните обязательные поля"
	case errors.Is(err, vault.ErrTooLarge):
		return "файл больше 8 МБ"
	case errors.Is(err, vault.ErrNotFound):
		return "запись не найдена"
	default:
		return "внутренняя ошибка сервера"
	}
}

func vaultStatus(err error) int {
	switch {
	case errors.Is(err, vault.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, vault.ErrInvalidItem), errors.Is(err, vault.ErrTooLarge):
		return http.StatusBadRequest
	case errors.Is(err, vault.ErrConflict):
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}

func authStatus(err error) int {
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials), errors.Is(err, auth.ErrInvalidToken), errors.Is(err, auth.ErrSessionExpired):
		return http.StatusUnauthorized
	case errors.Is(err, auth.ErrLoginTaken), errors.Is(err, auth.ErrWeakPassword), errors.Is(err, auth.ErrEmptyLogin):
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}

func writeWebError(w http.ResponseWriter, err error) {
	code := vaultStatus(err)
	msg := err.Error()
	if code >= 500 {
		msg = http.StatusText(code)
	}
	http.Error(w, msg, code)
}

func writeVaultErr(w http.ResponseWriter, err error) {
	code := vaultStatus(err)
	msg := humanVaultErr(err)
	if errors.Is(err, vault.ErrNotFound) {
		msg = "not found"
	}
	if code >= 500 {
		msg = "internal error"
	}
	writeJSON(w, code, map[string]string{"error": msg})
}

func writeAuthErr(w http.ResponseWriter, err error) {
	code := authStatus(err)
	msg := humanAuthErr(err)
	if code >= 500 {
		msg = "internal error"
	}
	writeJSON(w, code, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func decodeJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}

func (d Deps) apiHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (d Deps) apiVersion(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, version.Current())
}

func (d Deps) apiClientList(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"clients": d.Download.List()})
}

func (d Deps) apiClientDownload(w http.ResponseWriter, r *http.Request) {
	b, path, err := d.Download.Get(chi.URLParam(r, "platform"))
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "client binary not built"})
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+b.Filename+`"`)
	http.ServeFile(w, r, path)
}

type authBody struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

func (d Deps) apiRegister(w http.ResponseWriter, r *http.Request) {
	var body authBody
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	tokens, err := d.Auth.Register(r.Context(), body.Login, body.Password)
	if err != nil {
		writeAuthErr(w, err)
		return
	}
	setAuthCookies(w, d.Cfg, tokens)
	writeJSON(w, http.StatusCreated, tokens)
}

func (d Deps) apiLogin(w http.ResponseWriter, r *http.Request) {
	var body authBody
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	tokens, err := d.Auth.Login(r.Context(), body.Login, body.Password)
	if err != nil {
		writeAuthErr(w, err)
		return
	}
	setAuthCookies(w, d.Cfg, tokens)
	writeJSON(w, http.StatusOK, tokens)
}

func (d Deps) apiLogout(w http.ResponseWriter, r *http.Request) {
	if p, ok := requestPrincipal(r); ok {
		_ = d.Auth.Logout(r.Context(), p.SessionID)
	}
	clearAuthCookies(w, d.Cfg)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (d Deps) apiRefresh(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	_ = decodeJSON(r, &body)
	if body.RefreshToken == "" {
		if c, err := r.Cookie(cookieRefresh); err == nil {
			body.RefreshToken = c.Value
		}
	}
	tokens, err := d.Auth.Refresh(r.Context(), body.RefreshToken)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid refresh token"})
		return
	}
	setAuthCookies(w, d.Cfg, tokens)
	writeJSON(w, http.StatusOK, tokens)
}

func (d Deps) apiListItems(w http.ResponseWriter, r *http.Request) {
	p, _ := requestPrincipal(r)
	items, err := d.Vault.List(r.Context(), p.UserID, p.KEK, r.URL.Query().Get("type"))
	if err != nil {
		writeVaultErr(w, err)
		return
	}
	if items == nil {
		items = []vault.Item{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (d Deps) apiGetItem(w http.ResponseWriter, r *http.Request) {
	p, _ := requestPrincipal(r)
	it, err := d.Vault.GetBinary(r.Context(), p.UserID, p.KEK, chi.URLParam(r, "id"))
	if err != nil {
		writeVaultErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, it)
}

func (d Deps) apiCreateItem(w http.ResponseWriter, r *http.Request) {
	p, _ := requestPrincipal(r)
	var it vault.Item
	if err := decodeJSON(r, &it); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	created, err := d.Vault.Create(r.Context(), p.UserID, p.KEK, it)
	if err != nil {
		writeVaultErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (d Deps) apiUpdateItem(w http.ResponseWriter, r *http.Request) {
	p, _ := requestPrincipal(r)
	var it vault.Item
	if err := decodeJSON(r, &it); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	it.ID = chi.URLParam(r, "id")
	updated, err := d.Vault.Update(r.Context(), p.UserID, p.KEK, it)
	if err != nil {
		writeVaultErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (d Deps) apiDeleteItem(w http.ResponseWriter, r *http.Request) {
	p, _ := requestPrincipal(r)
	if err := d.Vault.Delete(r.Context(), p.UserID, chi.URLParam(r, "id"), "api"); err != nil {
		writeVaultErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (d Deps) apiSync(w http.ResponseWriter, r *http.Request) {
	p, _ := requestPrincipal(r)
	var body struct {
		SinceVersion int64        `json:"since_version"`
		Items        []vault.Item `json:"items"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	res, err := d.Vault.Sync(r.Context(), p.UserID, p.KEK, body.SinceVersion, body.Items, "api")
	if err != nil {
		writeVaultErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func serveSwagger(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(swaggerJSON)
}
