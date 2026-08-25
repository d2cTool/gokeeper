package grpcx_test

import (
	"context"
	"net"
	"path/filepath"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"gokeeper/internal/auth"
	"gokeeper/internal/cryptox"
	"gokeeper/internal/storage/sqlite"
	"gokeeper/internal/transport/grpc/pb"
	"gokeeper/internal/transport/grpcx"
	"gokeeper/internal/vault"
)

func setupGRPC(t *testing.T) (*grpc.ClientConn, *auth.Service) {
	t.Helper()
	db, err := sqlite.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlite.Close(db) })
	master, _ := cryptox.NewSalt(32)
	secret, _ := cryptox.NewSalt(32)
	authSvc := auth.NewService(db, secret, master)
	srv := grpc.NewServer(grpc.UnaryInterceptor(grpcx.UnaryAuth(authSvc)))
	grpcx.Register(srv, &grpcx.Server{Auth: authSvc, Vault: vault.NewService(db)})
	lis := bufconn.Listen(1024 * 1024)
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn, authSvc
}

func TestGRPCRegisterLoginVaultSync(t *testing.T) {
	conn, _ := setupGRPC(t)
	ctx := context.Background()
	authc := pb.NewAuthServiceClient(conn)
	tok, err := authc.Register(ctx, pb.AuthRequest_builder{Login: "ada", Password: "supersecret"}.Build())
	if err != nil || tok.GetAccessToken() == "" {
		t.Fatalf("register %v %+v", err, tok)
	}
	if _, err := authc.Login(ctx, pb.AuthRequest_builder{Login: "ada", Password: "wrongpassx"}.Build()); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("bad login: %v", err)
	}
	vaultc := pb.NewVaultServiceClient(conn)
	if _, err := vaultc.List(ctx, pb.ListRequest_builder{}.Build()); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no token: %v", err)
	}
	actx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+tok.GetAccessToken())
	created, err := vaultc.Create(actx, pb.UpsertRequest_builder{
		Type: "login", Metadata: "job",
		Login: pb.LoginPayload_builder{Url: "https://a", Username: "u", Password: "p"}.Build(),
	}.Build())
	if err != nil {
		t.Fatal(err)
	}
	got, err := vaultc.Get(actx, pb.GetRequest_builder{Id: created.GetId()}.Build())
	if err != nil || got.GetLogin().GetUsername() != "u" {
		t.Fatalf("get %v %+v", err, got)
	}
	_, err = vaultc.Update(actx, pb.UpsertRequest_builder{
		Id: created.GetId(), Type: "login",
		Login: pb.LoginPayload_builder{Url: "https://b", Username: "u2", Password: "p2"}.Build(),
	}.Build())
	if err != nil {
		t.Fatal(err)
	}
	list, err := vaultc.List(actx, pb.ListRequest_builder{Type: "login"}.Build())
	if err != nil || len(list.GetItems()) != 1 {
		t.Fatalf("list %v %+v", err, list)
	}
	sync, err := vaultc.Sync(actx, pb.SyncRequest_builder{SinceVersion: 0}.Build())
	if err != nil || sync.GetServerVersion() < 1 {
		t.Fatalf("sync %v %+v", err, sync)
	}
	if _, err := vaultc.Delete(actx, pb.DeleteRequest_builder{Id: created.GetId()}.Build()); err != nil {
		t.Fatal(err)
	}
	if _, err := vaultc.Get(actx, pb.GetRequest_builder{Id: created.GetId()}.Build()); status.Code(err) != codes.NotFound {
		t.Fatalf("deleted: %v", err)
	}
	if _, err := authc.Logout(actx, pb.LogoutRequest_builder{}.Build()); err != nil {
		t.Fatal(err)
	}
}
