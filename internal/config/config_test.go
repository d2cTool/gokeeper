package config

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDevCreatesKeys(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APP_ENV", "dev")
	t.Setenv("DATA_DIR", dir)
	t.Setenv("SERVER_MASTER_KEY", "")
	t.Setenv("JWT_SECRET", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.MasterKey) != 32 || len(cfg.JWTSecret) != 32 {
		t.Fatalf("keys %+v", cfg)
	}
	if _, err := os.Stat(filepath.Join(dir, "master.key")); err != nil {
		t.Fatal(err)
	}
}

func TestLoadProdRequiresEnv(t *testing.T) {
	t.Setenv("APP_ENV", "prod")
	t.Setenv("DATA_DIR", t.TempDir())
	t.Setenv("SERVER_MASTER_KEY", "")
	t.Setenv("JWT_SECRET", "")
	if _, err := Load(); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseKeyHex(t *testing.T) {
	raw := hex.EncodeToString(make([]byte, 32))
	got, err := parseKey(raw, 32)
	if err != nil || len(got) != 32 {
		t.Fatalf("%v %v", got, err)
	}
	raw32 := string(make([]byte, 32))
	got, err = parseKey(raw32, 32)
	if err != nil || len(got) != 32 {
		t.Fatalf("raw %v %v", got, err)
	}
	if _, err := parseKey("nope", 32); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestLoadFromEnvKeys(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APP_ENV", "prod")
	t.Setenv("DATA_DIR", dir)
	key := hex.EncodeToString(make([]byte, 32))
	t.Setenv("SERVER_MASTER_KEY", key)
	t.Setenv("JWT_SECRET", key)
	t.Setenv("HTTP_ADDR", ":1")
	t.Setenv("GRPC_ADDR", ":2")
	t.Setenv("CLIENT_BINARIES_DIR", "x")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTPAddr != ":1" || cfg.GRPCAddr != ":2" || cfg.Dev {
		t.Fatalf("%+v", cfg)
	}
}
