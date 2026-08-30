package auth_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"gokeeper/internal/auth"
	"gokeeper/internal/cryptox"
	"gokeeper/internal/storage/sqlite"
)

func setupAuthDB(t *testing.T) (*auth.Service, *sql.DB) {
	t.Helper()
	db, err := sqlite.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlite.Close(db) })
	master, _ := cryptox.NewSalt(32)
	jwt, _ := cryptox.NewSalt(32)
	return auth.NewService(db, jwt, master), db
}

func setupAuth(t *testing.T) *auth.Service {
	s, _ := setupAuthDB(t)
	return s
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

func TestOpenSessionPurgesExpired(t *testing.T) {
	s, db := setupAuthDB(t)
	ctx := context.Background()
	first, err := s.Register(ctx, "dave", "supersecret")
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.Authenticate(ctx, first.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Login(ctx, "dave", "supersecret"); err != nil {
		t.Fatal(err)
	}
	if n := countSessions(t, db, p.UserID); n != 2 {
		t.Fatalf("live sessions=%d", n)
	}
	if _, err := db.Exec(`UPDATE sessions SET expires_at = 1 WHERE id = ?`, p.SessionID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Login(ctx, "dave", "supersecret"); err != nil {
		t.Fatal(err)
	}
	if n := countSessions(t, db, p.UserID); n != 2 {
		t.Fatalf("after purge sessions=%d", n)
	}
	if _, err := s.Authenticate(ctx, first.AccessToken); err != auth.ErrSessionExpired {
		t.Fatalf("expired session kept: %v", err)
	}
}

func countSessions(t *testing.T, db *sql.DB, userID string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE user_id = ?`, userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
