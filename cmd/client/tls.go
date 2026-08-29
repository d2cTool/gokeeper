package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"gokeeper/internal/clientcfg"
)

func loadVerifiedTLS(cfg clientcfg.Config, explicit string) (*tls.Config, error) {
	path, err := clientcfg.FindTLSCert(cfg, explicit)
	if errors.Is(err, os.ErrNotExist) {
		dest := clientcfg.PinnedTLSCertPath(cfg)
		if err := fetchAndTrustCert(cfg.Address, dest); err != nil {
			return nil, err
		}
		path = dest
	} else if err != nil {
		return nil, err
	}
	return clientcfg.LoadTLS(path)
}

func fetchAndTrustCert(addr, dest string) error {
	cert, err := fetchServerCert(addr)
	if err != nil {
		return fmt.Errorf("получить сертификат %s: %w", addr, err)
	}
	fmt.Fprintf(os.Stderr, "Сервер %s представил сертификат:\n  CN=%s\n  SHA-256=%s\n  до %s\n",
		addr, cert.Subject.CommonName, clientcfg.Fingerprint(cert), cert.NotAfter.UTC().Format(time.RFC3339))
	if !term.IsTerminal(int(syscall.Stdin)) {
		return fmt.Errorf("нет доверенного tls.crt: положите сертификат сервера в %s либо задайте --tls-cert / GOPHKEEPER_TLS_CERT", dest)
	}
	fmt.Fprint(os.Stderr, "Доверять этому сертификату и сохранить его? [y/N]: ")
	var ans string
	_, _ = fmt.Scanln(&ans)
	switch strings.ToLower(strings.TrimSpace(ans)) {
	case "y", "yes":
	default:
		return fmt.Errorf("сертификат отклонён")
	}
	if err := clientcfg.SaveCertPEM(dest, cert); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "сертификат сохранён в", dest)
	return nil
}

func fetchServerCert(addr string) (*x509.Certificate, error) {
	// Только чтобы показать сертификат пользователю. gRPC-сессия идёт уже с RootCAs.
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("сервер не представил сертификат")
	}
	return certs[0], nil
}
