package httpx

import (
	"net/http"
	"net/url"
	"time"

	"gokeeper/internal/auth"
	"gokeeper/internal/config"
)

const (
	cookieAccess  = "access_token"
	cookieRefresh = "refresh_token"
	cookieCSRF    = "csrf_token"
	cookieFlash   = "flash"
)

func setAuthCookies(w http.ResponseWriter, cfg config.Config, tokens auth.Tokens) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieAccess,
		Value:    tokens.AccessToken,
		Path:     "/",
		MaxAge:   int(auth.AccessTTL().Seconds()),
		HttpOnly: true,
		Secure:   cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     cookieRefresh,
		Value:    tokens.RefreshToken,
		Path:     "/auth/refresh",
		MaxAge:   int(auth.RefreshTTL().Seconds()),
		HttpOnly: true,
		Secure:   cfg.CookieSecure,
		SameSite: http.SameSiteStrictMode,
	})
}

func clearAuthCookies(w http.ResponseWriter, cfg config.Config) {
	expired := time.Unix(0, 0)
	http.SetCookie(w, &http.Cookie{
		Name: cookieAccess, Value: "", Path: "/", Expires: expired, MaxAge: -1,
		HttpOnly: true, Secure: cfg.CookieSecure, SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name: cookieRefresh, Value: "", Path: "/auth/refresh", Expires: expired, MaxAge: -1,
		HttpOnly: true, Secure: cfg.CookieSecure, SameSite: http.SameSiteStrictMode,
	})
}

func setFlash(w http.ResponseWriter, cfg config.Config, msg string) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieFlash,
		Value:    url.QueryEscape(msg),
		Path:     "/",
		MaxAge:   60,
		HttpOnly: true,
		Secure:   cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func takeFlash(w http.ResponseWriter, r *http.Request, cfg config.Config) string {
	c, err := r.Cookie(cookieFlash)
	if err != nil {
		return ""
	}
	http.SetCookie(w, &http.Cookie{
		Name: cookieFlash, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: cfg.CookieSecure, SameSite: http.SameSiteLaxMode,
	})
	msg, err := url.QueryUnescape(c.Value)
	if err != nil {
		return c.Value
	}
	return msg
}

func accessTokenFromRequest(r *http.Request) string {
	if c, err := r.Cookie(cookieAccess); err == nil && c.Value != "" {
		return c.Value
	}
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) > len(prefix) && h[:len(prefix)] == prefix {
		return h[len(prefix):]
	}
	return ""
}
