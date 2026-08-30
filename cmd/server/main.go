// Command server запускает HTTP (Chi + templ + Swagger) и gRPC API GophKeeper.
package main

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"

	"gokeeper/internal/auth"
	"gokeeper/internal/config"
	"gokeeper/internal/download"
	"gokeeper/internal/storage/sqlite"
	"gokeeper/internal/transport/grpcx"
	"gokeeper/internal/transport/httpx"
	"gokeeper/internal/vault"
	"gokeeper/pkg/version"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}
	db, err := sqlite.Open(cfg.SQLitePath)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	authSvc := auth.NewService(db, cfg.JWTSecret, cfg.MasterKey)
	vaultSvc := vault.NewService(db)
	httpHandler := httpx.NewRouter(httpx.Deps{
		Cfg:      cfg,
		Auth:     authSvc,
		Vault:    vaultSvc,
		Download: download.Catalog{Dir: cfg.ClientBinDir},
	})

	httpSrv := &http.Server{Addr: cfg.HTTPAddr, Handler: httpHandler, ReadHeaderTimeout: 5 * time.Second}
	grpcSrv := grpc.NewServer(grpcOpts(cfg, authSvc)...)
	grpcx.Register(grpcSrv, &grpcx.Server{Auth: authSvc, Vault: vaultSvc})
	reflection.Register(grpcSrv)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		ln, err := net.Listen("tcp", cfg.HTTPAddr)
		if err != nil {
			return err
		}
		log.Printf("http %s version=%s", cfg.HTTPAddr, version.String())
		if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
			return httpSrv.ServeTLS(ln, cfg.TLSCertFile, cfg.TLSKeyFile)
		}
		return httpSrv.Serve(ln)
	})
	g.Go(func() error {
		ln, err := net.Listen("tcp", cfg.GRPCAddr)
		if err != nil {
			return err
		}
		log.Printf("grpc %s", cfg.GRPCAddr)
		return grpcSrv.Serve(ln)
	})
	g.Go(func() error {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		grpcSrv.GracefulStop()
		return httpSrv.Shutdown(shutdownCtx)
	})
	if err := g.Wait(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func grpcOpts(cfg config.Config, authSvc *auth.Service) []grpc.ServerOption {
	opts := []grpc.ServerOption{grpc.UnaryInterceptor(grpcx.UnaryAuth(authSvc))}
	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			log.Fatalf("tls: %v", err)
		}
		opts = append(opts, grpc.Creds(credentials.NewServerTLSFromCert(&cert)))
	}
	return opts
}
