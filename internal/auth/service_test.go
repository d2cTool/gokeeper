package auth_test

import (
	"context"
	"path/filepath"
	"testing"

	"gokeeper/internal/auth"
	"gokeeper/internal/cryptox"
	"gokeeper/internal/storage/sqlite"
)

func setupAuth(t *testing.T) *auth.Service {
	t.Helper()
	db, err := sqlite.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlite.Close(db) })
	master, _ := cryptox.NewSalt(32)
	jwt, _ := cryptox.NewSalt(32)
	return auth.NewService(db, jwt, master)
}

func TestRegisterLoginAndAuth(t *testing.T) {
	s := setupAuth(t)
	ctx := context.Background()
	tokens, err := s.Register(ctx, "alice", "supersecret")
	if err != nil {
		t.Fatal(err)
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Fatal("empty tokens")
	}
	p, err := s.Authenticate(ctx, tokens.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if p.Login != "alice" || len(p.KEK) != 32 {
		t.Fatalf("principal=%+v", p)
	}
	loginTok, err := s.Login(ctx, "alice", "supersecret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, loginTok.AccessToken); err != nil {
		t.Fatal(err)
	}
}

func TestRegisterValidation(t *testing.T) {
	s := setupAuth(t)
	ctx := context.Background()
	if _, err := s.Register(ctx, "", "supersecret"); err != auth.ErrEmptyLogin {
		t.Fatalf("err=%v", err)
	}
	if _, err := s.Register(ctx, "bob", "short"); err != auth.ErrWeakPassword {
		t.Fatalf("err=%v", err)
	}
	if _, err := s.Register(ctx, "bob", "supersecret"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Register(ctx, "bob", "supersecret"); err != auth.ErrLoginTaken {
		t.Fatalf("err=%v", err)
	}
}

func TestLoginRejectsBadPassword(t *testing.T) {
	s := setupAuth(t)
	ctx := context.Background()
	if _, err := s.Register(ctx, "eve", "supersecret"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Login(ctx, "eve", "wrongpass"); err != auth.ErrInvalidCredentials {
		t.Fatalf("err=%v", err)
	}
	if _, err := s.Login(ctx, "nobody", "supersecret"); err != auth.ErrInvalidCredentials {
		t.Fatalf("err=%v", err)
	}
}

func TestRefreshAndLogout(t *testing.T) {
	s := setupAuth(t)
	ctx := context.Background()
	tok, err := s.Register(ctx, "carol", "supersecret")
	if err != nil {
		t.Fatal(err)
	}
	next, err := s.Refresh(ctx, tok.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if next.AccessToken == "" {
		t.Fatal("empty refresh access")
	}
	p, err := s.Authenticate(ctx, tok.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Logout(ctx, p.SessionID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, next.AccessToken); err != auth.ErrSessionExpired {
		t.Fatalf("err=%v", err)
	}
}
