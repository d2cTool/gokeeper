package grpcx

import (
	"context"
	"errors"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"gokeeper/internal/auth"
	"gokeeper/internal/transport/grpc/pb"
	"gokeeper/internal/vault"
)

// Server реализует gRPC-сервисы поверх общих доменных сервисов.
type Server struct {
	pb.UnimplementedAuthServiceServer
	pb.UnimplementedVaultServiceServer
	Auth  *auth.Service
	Vault *vault.Service
}

// Register вешает обработчики на gRPC-сервер.
func Register(gs *grpc.Server, s *Server) {
	pb.RegisterAuthServiceServer(gs, s)
	pb.RegisterVaultServiceServer(gs, s)
}

// UnaryAuth извлекает JWT из metadata authorization и кладёт Principal в context.
func UnaryAuth(authSvc *auth.Service) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if info.FullMethod == pb.AuthService_Register_FullMethodName ||
			info.FullMethod == pb.AuthService_Login_FullMethodName {
			return handler(ctx, req)
		}
		tok := tokenFromMD(ctx)
		if tok == "" {
			return nil, status.Error(codes.Unauthenticated, "missing token")
		}
		p, err := authSvc.Authenticate(ctx, tok)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}
		return handler(withPrincipal(ctx, p), req)
	}
}

type ctxKey int

const ctxPrincipal ctxKey = 1

func withPrincipal(ctx context.Context, p auth.Principal) context.Context {
	return context.WithValue(ctx, ctxPrincipal, p)
}

func principalFrom(ctx context.Context) (auth.Principal, bool) {
	p, ok := ctx.Value(ctxPrincipal).(auth.Principal)
	return p, ok
}

func tokenFromMD(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	for _, key := range []string{"authorization", "Authorization"} {
		vals := md.Get(key)
		if len(vals) == 0 {
			continue
		}
		v := vals[0]
		const p = "Bearer "
		if len(v) > len(p) && v[:len(p)] == p {
			return v[len(p):]
		}
		return v
	}
	return ""
}

// Register создаёт пользователя.
func (s *Server) Register(ctx context.Context, req *pb.AuthRequest) (*pb.TokenResponse, error) {
	tokens, err := s.Auth.Register(ctx, req.GetLogin(), req.GetPassword())
	if err != nil {
		return nil, mapAuthErr(err)
	}
	return tokensToPB(tokens), nil
}

// Login проверяет пароль и выдаёт JWT.
func (s *Server) Login(ctx context.Context, req *pb.AuthRequest) (*pb.TokenResponse, error) {
	tokens, err := s.Auth.Login(ctx, req.GetLogin(), req.GetPassword())
	if err != nil {
		return nil, mapAuthErr(err)
	}
	return tokensToPB(tokens), nil
}

// Logout закрывает сессию.
func (s *Server) Logout(ctx context.Context, _ *pb.LogoutRequest) (*pb.Empty, error) {
	p, ok := principalFrom(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "unauthorized")
	}
	if err := s.Auth.Logout(ctx, p.SessionID); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return pb.Empty_builder{}.Build(), nil
}

// List возвращает записи сейфа.
func (s *Server) List(ctx context.Context, req *pb.ListRequest) (*pb.ListResponse, error) {
	p, err := mustPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	items, err := s.Vault.List(ctx, p.UserID, p.KEK, req.GetType())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	out := make([]*pb.Item, 0, len(items))
	for _, it := range items {
		out = append(out, itemToPB(it))
	}
	return pb.ListResponse_builder{Items: out}.Build(), nil
}

// Get возвращает запись, для binary — с телом файла.
func (s *Server) Get(ctx context.Context, req *pb.GetRequest) (*pb.Item, error) {
	p, err := mustPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	it, err := s.Vault.GetBinary(ctx, p.UserID, p.KEK, req.GetId())
	if err != nil {
		return nil, mapVaultErr(err)
	}
	return itemToPB(it), nil
}

// Create добавляет запись.
func (s *Server) Create(ctx context.Context, req *pb.UpsertRequest) (*pb.Item, error) {
	p, err := mustPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	it := upsertToItem(req.GetId(), req.GetType(), req.GetMetadata(), req.GetLogin(), req.GetText(), req.GetBinary(), req.GetCard(), 0, 0, false)
	it.Origin = "grpc"
	created, err := s.Vault.Create(ctx, p.UserID, p.KEK, it)
	if err != nil {
		return nil, mapVaultErr(err)
	}
	return itemToPB(created), nil
}

// Update изменяет запись.
func (s *Server) Update(ctx context.Context, req *pb.UpsertRequest) (*pb.Item, error) {
	p, err := mustPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	it := upsertToItem(req.GetId(), req.GetType(), req.GetMetadata(), req.GetLogin(), req.GetText(), req.GetBinary(), req.GetCard(), 0, 0, false)
	it.Origin = "grpc"
	updated, err := s.Vault.Update(ctx, p.UserID, p.KEK, it)
	if err != nil {
		return nil, mapVaultErr(err)
	}
	return itemToPB(updated), nil
}

// Delete помечает запись удалённой.
func (s *Server) Delete(ctx context.Context, req *pb.DeleteRequest) (*pb.Empty, error) {
	p, err := mustPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.Vault.Delete(ctx, p.UserID, req.GetId(), "grpc"); err != nil {
		return nil, mapVaultErr(err)
	}
	return pb.Empty_builder{}.Build(), nil
}

// Sync выполняет LWW-синхронизацию.
func (s *Server) Sync(ctx context.Context, req *pb.SyncRequest) (*pb.SyncResponse, error) {
	p, err := mustPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	var incoming []vault.Item
	for _, it := range req.GetItems() {
		incoming = append(incoming, itemFromPB(it))
	}
	res, err := s.Vault.Sync(ctx, p.UserID, p.KEK, req.GetSinceVersion(), incoming, "grpc")
	if err != nil {
		return nil, mapVaultErr(err)
	}
	out := make([]*pb.Item, 0, len(res.Items))
	for _, it := range res.Items {
		out = append(out, itemToPB(it))
	}
	return pb.SyncResponse_builder{Items: out, ServerVersion: res.ServerVersion}.Build(), nil
}

func mustPrincipal(ctx context.Context) (auth.Principal, error) {
	p, ok := principalFrom(ctx)
	if !ok {
		return auth.Principal{}, status.Error(codes.Unauthenticated, "unauthorized")
	}
	return p, nil
}

func tokensToPB(t auth.Tokens) *pb.TokenResponse {
	return pb.TokenResponse_builder{
		AccessToken: t.AccessToken, RefreshToken: t.RefreshToken, ExpiresIn: t.ExpiresIn,
	}.Build()
}

func mapAuthErr(err error) error {
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		return status.Error(codes.Unauthenticated, err.Error())
	case errors.Is(err, auth.ErrLoginTaken), errors.Is(err, auth.ErrWeakPassword), errors.Is(err, auth.ErrEmptyLogin):
		return status.Error(codes.InvalidArgument, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}

func mapVaultErr(err error) error {
	switch {
	case errors.Is(err, vault.ErrNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, vault.ErrInvalidItem), errors.Is(err, vault.ErrTooLarge):
		return status.Error(codes.InvalidArgument, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}
