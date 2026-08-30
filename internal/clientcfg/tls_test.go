package clientcfg_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gokeeper/internal/clientcfg"
)

func TestLoadTLSTrustsPinnedCert(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeTestCert(t, dir)

	cfg, err := clientcfg.LoadTLS(certFile)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify must stay false")
	}
	if cfg.RootCAs == nil {
		t.Fatal("RootCAs is empty")
	}

	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte("ok"))
	}()

	client := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: cfg.RootCAs, ServerName: "localhost"}
	conn, err := tls.Dial("tcp", ln.Addr().String(), client)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
}

func TestLoadTLSRejectsGarbage(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.crt")
	if err := os.WriteFile(p, []byte("not-a-cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := clientcfg.LoadTLS(p); err == nil {
		t.Fatal("expected invalid pem")
	}
}

func TestFindTLSCert(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "custom.crt")
	if err := os.WriteFile(cert, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := clientcfg.Config{Path: filepath.Join(dir, "cfg.json")}

	got, err := clientcfg.FindTLSCert(cfg, cert)
	if err != nil || got != cert {
		t.Fatalf("explicit %q %v", got, err)
	}
	if _, err := clientcfg.FindTLSCert(cfg, filepath.Join(dir, "missing.crt")); err == nil {
		t.Fatal("expected missing explicit")
	}

	t.Setenv("GOPHKEEPER_TLS_CERT", cert)
	got, err = clientcfg.FindTLSCert(cfg, "")
	if err != nil || got != cert {
		t.Fatalf("env %q %v", got, err)
	}
	t.Setenv("GOPHKEEPER_TLS_CERT", "")

	pinned := filepath.Join(dir, "tls.crt")
	if err := os.WriteFile(pinned, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = clientcfg.FindTLSCert(cfg, "")
	if err != nil || got != pinned {
		t.Fatalf("pinned %q %v", got, err)
	}

	empty := clientcfg.Config{Path: filepath.Join(t.TempDir(), "cfg.json")}
	if _, err := clientcfg.FindTLSCert(empty, ""); err == nil || !os.IsNotExist(err) {
		t.Fatalf("want not exist, got %v", err)
	}
	if p := clientcfg.PinnedTLSCertPath(empty); p != filepath.Join(filepath.Dir(empty.Path), "tls.crt") {
		t.Fatalf("dest %s", p)
	}
}

func TestSaveCertAndFingerprint(t *testing.T) {
	dir := t.TempDir()
	certFile, _ := writeTestCert(t, dir)
	raw, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if fp := clientcfg.Fingerprint(cert); fp == "" || len(fp) < 64 {
		t.Fatalf("fingerprint %q", fp)
	}
	out := filepath.Join(dir, "pin", "tls.crt")
	if err := clientcfg.SaveCertPEM(out, cert); err != nil {
		t.Fatal(err)
	}
	if _, err := clientcfg.LoadTLS(out); err != nil {
		t.Fatal(err)
	}
	if err := clientcfg.SaveCertPEM(out, nil); err == nil {
		t.Fatal("expected empty cert error")
	}
}

func writeTestCert(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"GophKeeper"}, CommonName: "localhost"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile = filepath.Join(dir, "tls.crt")
	keyFile = filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}
