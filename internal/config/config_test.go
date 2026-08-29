package config

import (
	"crypto/tls"
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
	t.Setenv("TLS_CERT_FILE", "")
	t.Setenv("TLS_KEY_FILE", "")
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
	if cfg.TLSCertFile != filepath.Join(dir, "tls.crt") || cfg.TLSKeyFile != filepath.Join(dir, "tls.key") {
		t.Fatalf("tls paths %+v", cfg)
	}
	if _, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil {
		t.Fatal(err)
	}
	if !cfg.CookieSecure {
		t.Fatal("cookie must be secure when TLS is on")
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
	t.Setenv("TLS_CERT_FILE", "")
	t.Setenv("TLS_KEY_FILE", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTPAddr != ":1" || cfg.GRPCAddr != ":2" || cfg.Dev {
		t.Fatalf("%+v", cfg)
	}
	if _, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil {
		t.Fatal(err)
	}
}

func TestLoadTLSFromEnv(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APP_ENV", "dev")
	t.Setenv("DATA_DIR", dir)
	t.Setenv("SERVER_MASTER_KEY", "")
	t.Setenv("JWT_SECRET", "")
	cert := filepath.Join(dir, "custom.crt")
	key := filepath.Join(dir, "custom.key")
	if err := writeSelfSigned(cert, key); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TLS_CERT_FILE", cert)
	t.Setenv("TLS_KEY_FILE", key)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TLSCertFile != cert || cfg.TLSKeyFile != key {
		t.Fatalf("want env paths, got %+v", cfg)
	}
	if _, err := os.Stat(filepath.Join(dir, "tls.crt")); !os.IsNotExist(err) {
		t.Fatal("must not generate default tls when env is set")
	}
}

func TestLoadTLSRequiresBothEnv(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APP_ENV", "dev")
	t.Setenv("DATA_DIR", dir)
	t.Setenv("SERVER_MASTER_KEY", "")
	t.Setenv("JWT_SECRET", "")
	t.Setenv("TLS_CERT_FILE", filepath.Join(dir, "only.crt"))
	t.Setenv("TLS_KEY_FILE", "")
	if _, err := Load(); err == nil {
		t.Fatal("expected error when only TLS_CERT_FILE is set")
	}

	t.Setenv("TLS_CERT_FILE", "")
	t.Setenv("TLS_KEY_FILE", filepath.Join(dir, "only.key"))
	if _, err := Load(); err == nil {
		t.Fatal("expected error when only TLS_KEY_FILE is set")
	}
}

func TestLoadTLSReusesExistingPair(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APP_ENV", "dev")
	t.Setenv("DATA_DIR", dir)
	t.Setenv("SERVER_MASTER_KEY", "")
	t.Setenv("JWT_SECRET", "")
	t.Setenv("TLS_CERT_FILE", "")
	t.Setenv("TLS_KEY_FILE", "")
	cert := filepath.Join(dir, "tls.crt")
	key := filepath.Join(dir, "tls.key")
	if err := os.WriteFile(cert, []byte("KEEP-CERT"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("KEEP-KEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TLSCertFile != cert || cfg.TLSKeyFile != key {
		t.Fatalf("paths %+v", cfg)
	}
	gotCert, err := os.ReadFile(cert)
	if err != nil || string(gotCert) != "KEEP-CERT" {
		t.Fatalf("cert rewritten: %q %v", gotCert, err)
	}
	gotKey, err := os.ReadFile(key)
	if err != nil || string(gotKey) != "KEEP-KEY" {
		t.Fatalf("key rewritten: %q %v", gotKey, err)
	}
}

func TestLoadTLSGeneratesWhenKeyMissing(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APP_ENV", "dev")
	t.Setenv("DATA_DIR", dir)
	t.Setenv("SERVER_MASTER_KEY", "")
	t.Setenv("JWT_SECRET", "")
	t.Setenv("TLS_CERT_FILE", "")
	t.Setenv("TLS_KEY_FILE", "")
	if err := os.WriteFile(filepath.Join(dir, "tls.crt"), []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil {
		t.Fatal(err)
	}
}

func TestLoadTLSGenerateError(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APP_ENV", "dev")
	t.Setenv("DATA_DIR", dir)
	t.Setenv("SERVER_MASTER_KEY", "")
	t.Setenv("JWT_SECRET", "")
	t.Setenv("TLS_CERT_FILE", "")
	t.Setenv("TLS_KEY_FILE", "")
	if err := os.Mkdir(filepath.Join(dir, "tls.crt"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil {
		t.Fatal("expected generate error when tls.crt is a directory")
	}
}

func TestWriteSelfSignedWriteErrors(t *testing.T) {
	dir := t.TempDir()
	if err := writeSelfSigned(filepath.Join(dir, "missing", "tls.crt"), filepath.Join(dir, "tls.key")); err == nil {
		t.Fatal("expected cert write error")
	}

	cert := filepath.Join(dir, "ok.crt")
	keyDir := filepath.Join(dir, "tls.key")
	if err := os.Mkdir(keyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeSelfSigned(cert, keyDir); err == nil {
		t.Fatal("expected key write error")
	}
	if _, err := os.Stat(cert); !os.IsNotExist(err) {
		t.Fatal("cert must be removed after key write failure")
	}
}

func TestLoadKeyFromFilesAndErrors(t *testing.T) {
	dir := t.TempDir()
	key := hex.EncodeToString(make([]byte, 32))
	if err := os.WriteFile(filepath.Join(dir, "master.key"), []byte(key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "jwt.secret"), []byte(key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("APP_ENV", "dev")
	t.Setenv("DATA_DIR", dir)
	t.Setenv("SERVER_MASTER_KEY", "")
	t.Setenv("JWT_SECRET", "")
	t.Setenv("TLS_CERT_FILE", "")
	t.Setenv("TLS_KEY_FILE", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.MasterKey) != 32 || len(cfg.JWTSecret) != 32 {
		t.Fatalf("keys %+v", cfg)
	}

	t.Setenv("SERVER_MASTER_KEY", "short")
	if _, err := Load(); err == nil {
		t.Fatal("expected invalid env key")
	}
	t.Setenv("SERVER_MASTER_KEY", "")
	if err := os.WriteFile(filepath.Join(dir, "jwt.secret"), []byte("nope\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil {
		t.Fatal("expected invalid key file")
	}
}

func TestLoadProdRequiresJWT(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APP_ENV", "prod")
	t.Setenv("DATA_DIR", dir)
	t.Setenv("SERVER_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))
	t.Setenv("JWT_SECRET", "")
	t.Setenv("TLS_CERT_FILE", "")
	t.Setenv("TLS_KEY_FILE", "")
	if _, err := Load(); err == nil {
		t.Fatal("expected jwt required in prod")
	}
}

func TestLoadDataDirAndKeyWriteErrors(t *testing.T) {
	blocked := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("APP_ENV", "dev")
	t.Setenv("DATA_DIR", blocked)
	t.Setenv("SERVER_MASTER_KEY", "")
	t.Setenv("JWT_SECRET", "")
	if _, err := Load(); err == nil {
		t.Fatal("expected data dir error")
	}

	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "master.key"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DATA_DIR", dir)
	t.Setenv("TLS_CERT_FILE", "")
	t.Setenv("TLS_KEY_FILE", "")
	if _, err := Load(); err == nil {
		t.Fatal("expected write key error")
	}
}
