package httpx

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"gokeeper/internal/config"
	"gokeeper/internal/cryptox"
)

func csrfMiddleware(cfg config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := csrfCookie(r)
			if token == "" {
				raw, err := cryptox.NewSalt(16)
				if err != nil {
					http.Error(w, "csrf", http.StatusInternalServerError)
					return
				}
				token = hexOf(raw)
				http.SetCookie(w, &http.Cookie{
					Name:     cookieCSRF,
					Value:    token,
					Path:     "/",
					HttpOnly: false,
					Secure:   cfg.CookieSecure,
					SameSite: http.SameSiteLaxMode,
				})
			}
			r = r.WithContext(withCSRF(r.Context(), token))

			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}
			if strings.HasPrefix(r.URL.Path, "/api/") {
				next.ServeHTTP(w, r)
				return
			}
			formTok := r.Header.Get("X-CSRF-Token")
			if formTok == "" {
				formTok = r.FormValue("csrf")
			}
			if subtle.ConstantTimeCompare([]byte(formTok), []byte(token)) != 1 {
				http.Error(w, "invalid csrf token", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func csrfCookie(r *http.Request) string {
	c, err := r.Cookie(cookieCSRF)
	if err != nil {
		return ""
	}
	return c.Value
}

func hexOf(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hex[v>>4]
		out[i*2+1] = hex[v&0x0f]
	}
	return string(out)
}
