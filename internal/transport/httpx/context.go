package httpx

import (
	"context"
	"net/http"

	"gokeeper/internal/auth"
)

type ctxKey int

const (
	ctxPrincipal ctxKey = iota
	ctxCSRF
)

func withPrincipal(ctx context.Context, p auth.Principal) context.Context {
	return context.WithValue(ctx, ctxPrincipal, p)
}

// PrincipalFrom достаёт владельца сессии из контекста запроса.
func PrincipalFrom(ctx context.Context) (auth.Principal, bool) {
	p, ok := ctx.Value(ctxPrincipal).(auth.Principal)
	return p, ok
}

func withCSRF(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, ctxCSRF, token)
}

func csrfFrom(ctx context.Context) string {
	t, _ := ctx.Value(ctxCSRF).(string)
	return t
}

func requestPrincipal(r *http.Request) (auth.Principal, bool) {
	return PrincipalFrom(r.Context())
}
