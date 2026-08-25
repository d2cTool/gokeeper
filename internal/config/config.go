package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Config описывает параметры процесса сервера.
type Config struct {
	HTTPAddr     string
	GRPCAddr     string
	SQLitePath   string
	MasterKey    []byte
	JWTSecret    []byte
	ClientBinDir string
	TLSCertFile  string
	TLSKeyFile   string
	CookieSecure bool
	Dev          bool
}

// Load читает конфигурацию из окружения.
// В режиме разработки (APP_ENV != prod) недостающие ключи создаются в data/.
func Load() (Config, error) {
	dev := !strings.EqualFold(os.Getenv("APP_ENV"), "prod")
	dataDir := envOr("DATA_DIR", "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return Config{}, fmt.Errorf("create data dir: %w", err)
	}

	master, err := loadKey("SERVER_MASTER_KEY", filepath.Join(dataDir, "master.key"), 32, dev)
	if err != nil {
		return Config{}, err
	}
	jwt, err := loadKey("JWT_SECRET", filepath.Join(dataDir, "jwt.secret"), 32, dev)
	if err != nil {
		return Config{}, err
	}

	tlsCert := os.Getenv("TLS_CERT_FILE")
	tlsKey := os.Getenv("TLS_KEY_FILE")
	secure := !dev || (tlsCert != "" && tlsKey != "")

	return Config{
		HTTPAddr:     envOr("HTTP_ADDR", ":8080"),
		GRPCAddr:     envOr("GRPC_ADDR", ":9090"),
		SQLitePath:   envOr("SQLITE_PATH", filepath.Join(dataDir, "gophkeeper.db")),
		MasterKey:    master,
		JWTSecret:    jwt,
		ClientBinDir: envOr("CLIENT_BINARIES_DIR", filepath.Join("bin", "clients")),
		TLSCertFile:  tlsCert,
		TLSKeyFile:   tlsKey,
		CookieSecure: secure,
		Dev:          dev,
	}, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func loadKey(envName, filePath string, n int, dev bool) ([]byte, error) {
	if raw := os.Getenv(envName); raw != "" {
		key, err := parseKey(raw, n)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", envName, err)
		}
		return key, nil
	}
	if !dev {
		return nil, fmt.Errorf("%s is required in prod", envName)
	}
	if b, err := os.ReadFile(filePath); err == nil {
		key, err := parseKey(strings.TrimSpace(string(b)), n)
		if err != nil {
			return nil, fmt.Errorf("%s file: %w", filePath, err)
		}
		return key, nil
	}
	key := make([]byte, n)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate %s: %w", envName, err)
	}
	if err := os.WriteFile(filePath, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("write %s: %w", filePath, err)
	}
	return key, nil
}

func parseKey(raw string, n int) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if b, err := hex.DecodeString(raw); err == nil && len(b) == n {
		return b, nil
	}
	if len(raw) == n {
		return []byte(raw), nil
	}
	return nil, fmt.Errorf("want %d bytes hex or raw, got %d chars", n, len(raw))
}
