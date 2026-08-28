package vault_test

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"

	"gokeeper/internal/cryptox"
	"gokeeper/internal/storage/sqlite"
	"gokeeper/internal/vault"
)

func setupVault(t *testing.T) (*vault.Service, string, []byte) {
	t.Helper()
	db, err := sqlite.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlite.Close(db) })
	if _, err := db.Exec(`INSERT INTO users (id, login, password_hash, enc_salt, created_at) VALUES ('u1','a','h',x'00',1)`); err != nil {
		t.Fatal(err)
	}
	kek, _ := cryptox.NewSalt(32)
	return vault.NewService(db), "u1", kek
}

func TestCRUDLogin(t *testing.T) {
	s, uid, kek := setupVault(t)
	ctx := context.Background()
	created, err := s.Create(ctx, uid, kek, vault.Item{
		Type: vault.TypeLogin,
		Login: &vault.LoginPayload{URL: "https://ex", Username: "u", Password: "p"},
		Metadata: "work",
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, uid, kek, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Login.Username != "u" || got.Metadata != "work" {
		t.Fatalf("%+v", got)
	}
	got.Login.Password = "p2"
	upd, err := s.Update(ctx, uid, kek, got)
	if err != nil {
		t.Fatal(err)
	}
	if upd.Version != 2 {
		t.Fatalf("version=%d", upd.Version)
	}
	list, err := s.List(ctx, uid, kek, "login")
	if err != nil || len(list) != 1 {
		t.Fatalf("list=%v err=%v", list, err)
	}
	if err := s.Delete(ctx, uid, created.ID, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, uid, kek, created.ID); err != vault.ErrNotFound {
		t.Fatalf("err=%v", err)
	}
}

func TestBinaryLimit(t *testing.T) {
	s, uid, kek := setupVault(t)
	_, err := s.Create(context.Background(), uid, kek, vault.Item{
		Type:   vault.TypeBinary,
		Binary: &vault.BinaryPayload{Filename: "a.bin", Data: bytes.Repeat([]byte{1}, 8<<20+1)},
	})
	if err != vault.ErrTooLarge {
		t.Fatalf("err=%v", err)
	}
}

func TestSyncLWW(t *testing.T) {
	s, uid, kek := setupVault(t)
	ctx := context.Background()
	a, err := s.Create(ctx, uid, kek, vault.Item{
		Type: vault.TypeText, Text: &vault.TextPayload{Title: "t", Body: "1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.Sync(ctx, uid, kek, 0, []vault.Item{{
		ID: a.ID, Type: vault.TypeText, Version: 10, UpdatedAt: a.UpdatedAt + 10,
		Text: &vault.TextPayload{Title: "t", Body: "2"},
	}}, "c2")
	if err != nil {
		t.Fatal(err)
	}
	if res.ServerVersion < 1 {
		t.Fatalf("ver=%d", res.ServerVersion)
	}
	got, _ := s.Get(ctx, uid, kek, a.ID)
	if got.Text.Body != "2" {
		t.Fatalf("body=%s", got.Text.Body)
	}
}

func TestTitle(t *testing.T) {
	it := vault.Item{Type: vault.TypeCard, Card: &vault.CardPayload{Number: "4111111111111111"}}
	if it.Title() != "•••• 1111" {
		t.Fatalf("title=%s", it.Title())
	}
}

func TestParseType(t *testing.T) {
	if _, err := vault.ParseType("nope"); !errors.Is(err, vault.ErrInvalidItem) {
		t.Fatalf("err=%v", err)
	}
	if _, err := vault.ParseType("login"); err != nil {
		t.Fatal(err)
	}
}

func TestCreateValidationAndBinaryRoundtrip(t *testing.T) {
	s, uid, kek := setupVault(t)
	ctx := context.Background()
	if _, err := s.Create(ctx, uid, kek, vault.Item{Type: vault.TypeLogin}); err != vault.ErrInvalidItem {
		t.Fatalf("err=%v", err)
	}
	created, err := s.Create(ctx, uid, kek, vault.Item{
		Type:   vault.TypeBinary,
		Binary: &vault.BinaryPayload{Filename: "a.bin", Data: []byte("hello")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.Binary != nil && len(created.Binary.Data) != 0 {
		t.Fatal("list payload must strip data")
	}
	full, err := s.GetBinary(ctx, uid, kek, created.ID)
	if err != nil || string(full.Binary.Data) != "hello" {
		t.Fatalf("%+v %v", full, err)
	}
	if _, err := s.Get(ctx, uid, kek, "missing"); err != vault.ErrNotFound {
		t.Fatalf("err=%v", err)
	}
	if err := s.Delete(ctx, uid, "missing", ""); err != vault.ErrNotFound {
		t.Fatalf("err=%v", err)
	}
}

func TestSyncOlderVersionIgnored(t *testing.T) {
	s, uid, kek := setupVault(t)
	ctx := context.Background()
	a, err := s.Create(ctx, uid, kek, vault.Item{
		Type: vault.TypeText, Text: &vault.TextPayload{Title: "t", Body: "new"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Sync(ctx, uid, kek, 0, []vault.Item{{
		ID: a.ID, Type: vault.TypeText, Version: 0, UpdatedAt: 1,
		Text: &vault.TextPayload{Title: "t", Body: "old"},
	}}, "old")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(ctx, uid, kek, a.ID)
	if got.Text.Body != "new" {
		t.Fatalf("body=%s", got.Text.Body)
	}
}
