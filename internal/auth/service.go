package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"gokeeper/internal/cryptox"
)

const (
	accessTTL  = 15 * time.Minute
	refreshTTL = 7 * 24 * time.Hour
	encSaltLen = 16
)

// Principal — владелец текущей сессии и ключ расшифровки хранилища.
type Principal struct {
	UserID    string
	Login     string
	SessionID string
	KEK       []byte
}

// Tokens — пара JWT access и opaque refresh.
type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

// Service выполняет регистрацию, вход и проверку сессий.
type Service struct {
	db        *sql.DB
	jwtSecret []byte
	masterKey []byte
}

// NewService создаёт сервис аутентификации.
func NewService(db *sql.DB, jwtSecret, masterKey []byte) *Service {
	return &Service{db: db, jwtSecret: jwtSecret, masterKey: masterKey}
}

// Register создаёт пользователя и сразу открывает сессию.
func (s *Service) Register(ctx context.Context, login, password string) (Tokens, error) {
	login = strings.TrimSpace(login)
	if login == "" {
		return Tokens{}, ErrEmptyLogin
	}
	if len(password) < 8 {
		return Tokens{}, ErrWeakPassword
	}

	hash, err := argon2id.CreateHash(password, argon2id.DefaultParams)
	if err != nil {
		return Tokens{}, fmt.Errorf("hash password: %w", err)
	}
	salt, err := cryptox.NewSalt(encSaltLen)
	if err != nil {
		return Tokens{}, err
	}

	id := uuid.NewString()
	now := time.Now().Unix()
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO users (id, login, password_hash, enc_salt, created_at) VALUES (?, ?, ?, ?, ?)`,
		id, login, hash, salt, now,
	)
	if err != nil {
		if isUnique(err) {
			return Tokens{}, ErrLoginTaken
		}
		return Tokens{}, fmt.Errorf("insert user: %w", err)
	}

	kek := cryptox.DeriveKEK(password, salt)
	return s.openSession(ctx, id, kek)
}

// Login проверяет пароль и открывает сессию с KEK.
func (s *Service) Login(ctx context.Context, login, password string) (Tokens, error) {
	login = strings.TrimSpace(login)
	var (
		id   string
		hash string
		salt []byte
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT id, password_hash, enc_salt FROM users WHERE login = ?`, login,
	).Scan(&id, &hash, &salt)
	if errors.Is(err, sql.ErrNoRows) {
		return Tokens{}, ErrInvalidCredentials
	}
	if err != nil {
		return Tokens{}, fmt.Errorf("select user: %w", err)
	}
	ok, err := argon2id.ComparePasswordAndHash(password, hash)
	if err != nil || !ok {
		return Tokens{}, ErrInvalidCredentials
	}
	kek := cryptox.DeriveKEK(password, salt)
	return s.openSession(ctx, id, kek)
}

// Logout удаляет сессию и связанные refresh-токены.
func (s *Service) Logout(ctx context.Context, sessionID string) error {
	if sessionID == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, sessionID)
	return err
}

// Refresh выпускает новую пару токенов по действующему refresh.
func (s *Service) Refresh(ctx context.Context, refreshToken string) (Tokens, error) {
	sum := hashToken(refreshToken)
	var (
		sessionID string
		userID    string
		expiresAt int64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT session_id, user_id, expires_at FROM refresh_tokens WHERE token_hash = ?`, sum,
	).Scan(&sessionID, &userID, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Tokens{}, ErrInvalidToken
	}
	if err != nil {
		return Tokens{}, fmt.Errorf("select refresh: %w", err)
	}
	if time.Now().Unix() >= expiresAt {
		return Tokens{}, ErrInvalidToken
	}

	var wrapped []byte
	err = s.db.QueryRowContext(ctx,
		`SELECT wrapped_kek FROM sessions WHERE id = ?`, sessionID,
	).Scan(&wrapped)
	if errors.Is(err, sql.ErrNoRows) {
		return Tokens{}, ErrSessionExpired
	}
	if err != nil {
		return Tokens{}, fmt.Errorf("select session: %w", err)
	}
	kek, err := cryptox.Open(s.masterKey, wrapped)
	if err != nil {
		return Tokens{}, fmt.Errorf("unwrap kek: %w", err)
	}

	if _, err := s.db.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE token_hash = ?`, sum); err != nil {
		return Tokens{}, err
	}
	return s.issueTokens(ctx, userID, sessionID, kek)
}

// Authenticate проверяет access JWT и достаёт KEK из сессии.
func (s *Service) Authenticate(ctx context.Context, accessToken string) (Principal, error) {
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(accessToken, claims, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, ErrInvalidToken
		}
		return s.jwtSecret, nil
	})
	if err != nil || !token.Valid {
		return Principal{}, ErrInvalidToken
	}

	userID, _ := claims["sub"].(string)
	sessionID, _ := claims["sid"].(string)
	login, _ := claims["login"].(string)
	if userID == "" || sessionID == "" {
		return Principal{}, ErrInvalidToken
	}

	var (
		wrapped   []byte
		expiresAt int64
	)
	err = s.db.QueryRowContext(ctx,
		`SELECT wrapped_kek, expires_at FROM sessions WHERE id = ? AND user_id = ?`,
		sessionID, userID,
	).Scan(&wrapped, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Principal{}, ErrSessionExpired
	}
	if err != nil {
		return Principal{}, fmt.Errorf("select session: %w", err)
	}
	if time.Now().Unix() >= expiresAt {
		return Principal{}, ErrSessionExpired
	}
	kek, err := cryptox.Open(s.masterKey, wrapped)
	if err != nil {
		return Principal{}, fmt.Errorf("unwrap kek: %w", err)
	}
	return Principal{UserID: userID, Login: login, SessionID: sessionID, KEK: kek}, nil
}

func (s *Service) openSession(ctx context.Context, userID string, kek []byte) (Tokens, error) {
	wrapped, err := cryptox.Seal(s.masterKey, kek)
	if err != nil {
		return Tokens{}, err
	}
	sessionID := uuid.NewString()
	exp := time.Now().Add(refreshTTL).Unix()
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (id, user_id, wrapped_kek, expires_at) VALUES (?, ?, ?, ?)`,
		sessionID, userID, wrapped, exp,
	); err != nil {
		return Tokens{}, fmt.Errorf("insert session: %w", err)
	}
	return s.issueTokens(ctx, userID, sessionID, kek)
}

func (s *Service) issueTokens(ctx context.Context, userID, sessionID string, kek []byte) (Tokens, error) {
	var login string
	if err := s.db.QueryRowContext(ctx, `SELECT login FROM users WHERE id = ?`, userID).Scan(&login); err != nil {
		return Tokens{}, fmt.Errorf("select login: %w", err)
	}

	now := time.Now()
	access := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   userID,
		"sid":   sessionID,
		"login": login,
		"exp":   now.Add(accessTTL).Unix(),
		"iat":   now.Unix(),
	})
	accessStr, err := access.SignedString(s.jwtSecret)
	if err != nil {
		return Tokens{}, fmt.Errorf("sign jwt: %w", err)
	}

	refreshRaw, err := randomToken(32)
	if err != nil {
		return Tokens{}, err
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO refresh_tokens (id, user_id, session_id, token_hash, expires_at) VALUES (?, ?, ?, ?, ?)`,
		uuid.NewString(), userID, sessionID, hashToken(refreshRaw), now.Add(refreshTTL).Unix(),
	); err != nil {
		return Tokens{}, fmt.Errorf("insert refresh: %w", err)
	}

	_ = kek
	return Tokens{
		AccessToken:  accessStr,
		RefreshToken: refreshRaw,
		ExpiresIn:    int64(accessTTL.Seconds()),
	}, nil
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func randomToken(n int) (string, error) {
	b, err := cryptox.NewSalt(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func isUnique(err error) bool {
	return err != nil && (strings.Contains(strings.ToLower(err.Error()), "unique") ||
		strings.Contains(err.Error(), "CONSTRAINT"))
}

// AccessTTL возвращает TTL access-токена — для тестов и cookie MaxAge.
func AccessTTL() time.Duration { return accessTTL }

// RefreshTTL возвращает TTL refresh-токена.
func RefreshTTL() time.Duration { return refreshTTL }

// NewNonce — совместимая обёртка на случай использования в тестах.
func NewNonce() ([]byte, error) {
	b := make([]byte, 12)
	_, err := rand.Read(b)
	return b, err
}
