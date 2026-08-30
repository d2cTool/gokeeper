package clientcfg

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// FindTLSCert ищет доверенный tls.crt: явный путь, GOPHKEEPER_TLS_CERT,
// каталог конфига, каталог бинарня, data/tls.crt рядом с CWD.
func FindTLSCert(cfg Config, explicit string) (string, error) {
	if explicit != "" {
		if err := regularFile(explicit); err != nil {
			return "", fmt.Errorf("tls-cert %s: %w", explicit, err)
		}
		return explicit, nil
	}
	if p := os.Getenv("GOPHKEEPER_TLS_CERT"); p != "" {
		if err := regularFile(p); err != nil {
			return "", fmt.Errorf("GOPHKEEPER_TLS_CERT: %w", err)
		}
		return p, nil
	}
	var candidates []string
	if cfg.Path != "" {
		candidates = append(candidates, filepath.Join(filepath.Dir(cfg.Path), "tls.crt"))
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "tls.crt"))
	}
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(cwd, "data", "tls.crt"))
	}
	for _, p := range candidates {
		if err := regularFile(p); err == nil {
			return p, nil
		}
	}
	return "", os.ErrNotExist
}

// PinnedTLSCertPath — куда сохранять сертификат после подтверждения.
func PinnedTLSCertPath(cfg Config) string {
	if cfg.Path != "" {
		return filepath.Join(filepath.Dir(cfg.Path), "tls.crt")
	}
	return "tls.crt"
}

// LoadTLS собирает tls.Config, который доверяет только certFile (без InsecureSkipVerify).
func LoadTLS(certFile string) (*tls.Config, error) {
	raw, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("read tls cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("invalid tls cert %s", certFile)
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    pool,
	}, nil
}

// SaveCertPEM пишет сертификат в PEM-файл.
func SaveCertPEM(path string, cert *x509.Certificate) error {
	if cert == nil {
		return fmt.Errorf("empty certificate")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return os.WriteFile(path, pemBytes, 0o600)
}

// Fingerprint возвращает SHA-256 отпечаток сертификата.
func Fingerprint(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	hexSum := strings.ToUpper(hex.EncodeToString(sum[:]))
	var b strings.Builder
	for i := 0; i < len(hexSum); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(hexSum[i : i+2])
	}
	return b.String()
}

func regularFile(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.IsDir() {
		return fmt.Errorf("is a directory")
	}
	return nil
}
