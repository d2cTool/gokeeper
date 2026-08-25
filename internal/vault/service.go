package vault

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"gokeeper/internal/cryptox"
)

// Ошибки хранилища.
var (
	ErrNotFound    = errors.New("item not found")
	ErrConflict    = errors.New("item version conflict")
	ErrTooLarge    = errors.New("binary payload exceeds 8 MiB")
	ErrInvalidItem = errors.New("invalid item payload")
)

const maxBinary = 8 << 20

// Service — CRUD и LWW-синхронизация зашифрованных записей.
type Service struct {
	db *sql.DB
}

// NewService создаёт сервис сейфа.
func NewService(db *sql.DB) *Service {
	return &Service{db: db}
}

// List возвращает расшифрованные незатомбстоуненные записи.
func (s *Service) List(ctx context.Context, userID string, kek []byte, typ string) ([]Item, error) {
	q := `SELECT id, type, ciphertext, version, updated_at, deleted, origin FROM items WHERE user_id = ? AND deleted = 0`
	args := []any{userID}
	if typ != "" {
		if _, err := ParseType(typ); err != nil {
			return nil, err
		}
		q += ` AND type = ?`
		args = append(args, typ)
	}
	q += ` ORDER BY updated_at DESC`
	return s.queryItems(ctx, kek, q, args...)
}

// Get возвращает одну запись владельца.
func (s *Service) Get(ctx context.Context, userID string, kek []byte, id string) (Item, error) {
	items, err := s.queryItems(ctx, kek,
		`SELECT id, type, ciphertext, version, updated_at, deleted, origin FROM items WHERE user_id = ? AND id = ? AND deleted = 0`,
		userID, id,
	)
	if err != nil {
		return Item{}, err
	}
	if len(items) == 0 {
		return Item{}, ErrNotFound
	}
	return items[0], nil
}

// Create сохраняет новую запись.
func (s *Service) Create(ctx context.Context, userID string, kek []byte, in Item) (Item, error) {
	if err := validate(in); err != nil {
		return Item{}, err
	}
	if in.ID == "" {
		in.ID = uuid.NewString()
	}
	in.Version = 1
	in.UpdatedAt = time.Now().UnixMicro()
	in.Deleted = false
	if in.Origin == "" {
		in.Origin = "server"
	}
	blob, err := encryptItem(kek, in)
	if err != nil {
		return Item{}, err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO items (id, user_id, type, ciphertext, version, updated_at, deleted, origin) VALUES (?, ?, ?, ?, ?, ?, 0, ?)`,
		in.ID, userID, string(in.Type), blob, in.Version, in.UpdatedAt, in.Origin,
	)
	if err != nil {
		return Item{}, fmt.Errorf("insert item: %w", err)
	}
	in.Binary = stripBinaryData(in.Binary)
	return in, nil
}

// Update перезаписывает запись и увеличивает version.
func (s *Service) Update(ctx context.Context, userID string, kek []byte, in Item) (Item, error) {
	if in.ID == "" {
		return Item{}, ErrInvalidItem
	}
	cur, err := s.Get(ctx, userID, kek, in.ID)
	if err != nil {
		return Item{}, err
	}
	if err := validate(in); err != nil {
		return Item{}, err
	}
	in.Type = cur.Type
	in.Version = cur.Version + 1
	in.UpdatedAt = time.Now().UnixMicro()
	in.Deleted = false
	if in.Origin == "" {
		in.Origin = cur.Origin
	}
	if in.Type == TypeBinary && (in.Binary == nil || len(in.Binary.Data) == 0) && cur.Binary != nil {
		in.Binary = cur.Binary
	}
	blob, err := encryptItem(kek, in)
	if err != nil {
		return Item{}, err
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE items SET ciphertext = ?, version = ?, updated_at = ?, deleted = 0, origin = ? WHERE id = ? AND user_id = ?`,
		blob, in.Version, in.UpdatedAt, in.Origin, in.ID, userID,
	)
	if err != nil {
		return Item{}, fmt.Errorf("update item: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return Item{}, ErrNotFound
	}
	in.Binary = stripBinaryData(in.Binary)
	return in, nil
}

// Delete помечает запись томбстоуном.
func (s *Service) Delete(ctx context.Context, userID, id, origin string) error {
	if origin == "" {
		origin = "server"
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE items SET deleted = 1, version = version + 1, updated_at = ?, origin = ? WHERE id = ? AND user_id = ? AND deleted = 0`,
		time.Now().UnixMicro(), origin, id, userID,
	)
	if err != nil {
		return fmt.Errorf("delete item: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// SyncResult — ответ LWW-синхронизации.
type SyncResult struct {
	Items         []Item
	ServerVersion int64
}

// Sync принимает локальные изменения клиента и отдаёт дельту с since.
func (s *Service) Sync(ctx context.Context, userID string, kek []byte, since int64, incoming []Item, origin string) (SyncResult, error) {
	if origin == "" {
		origin = "client"
	}
	for _, in := range incoming {
		if err := s.applyIncoming(ctx, userID, kek, in, origin); err != nil {
			return SyncResult{}, err
		}
	}
	items, err := s.queryItems(ctx, kek,
		`SELECT id, type, ciphertext, version, updated_at, deleted, origin FROM items WHERE user_id = ? AND version > ? ORDER BY version`,
		userID, since,
	)
	if err != nil {
		return SyncResult{}, err
	}
	var maxVer int64
	for _, it := range items {
		if it.Version > maxVer {
			maxVer = it.Version
		}
	}
	if maxVer == 0 {
		_ = s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version),0) FROM items WHERE user_id = ?`, userID).Scan(&maxVer)
	}
	return SyncResult{Items: items, ServerVersion: maxVer}, nil
}

func (s *Service) applyIncoming(ctx context.Context, userID string, kek []byte, in Item, origin string) error {
	if in.ID == "" {
		return ErrInvalidItem
	}
	if in.Deleted {
		_, err := s.db.ExecContext(ctx,
			`UPDATE items SET deleted = 1, version = version + 1, updated_at = ?, origin = ? WHERE id = ? AND user_id = ?`,
			time.Now().UnixMicro(), origin, in.ID, userID,
		)
		return err
	}
	if err := validate(in); err != nil {
		return err
	}
	in.Origin = origin
	var (
		ver       int64
		updatedAt int64
		curOrigin string
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT version, updated_at, origin FROM items WHERE id = ? AND user_id = ?`, in.ID, userID,
	).Scan(&ver, &updatedAt, &curOrigin)
	if errors.Is(err, sql.ErrNoRows) {
		in.Version = 1
		if in.UpdatedAt == 0 {
			in.UpdatedAt = time.Now().UnixMicro()
		}
		blob, err := encryptItem(kek, in)
		if err != nil {
			return err
		}
		_, err = s.db.ExecContext(ctx,
			`INSERT INTO items (id, user_id, type, ciphertext, version, updated_at, deleted, origin) VALUES (?, ?, ?, ?, ?, ?, 0, ?)`,
			in.ID, userID, string(in.Type), blob, in.Version, in.UpdatedAt, in.Origin,
		)
		return err
	}
	if err != nil {
		return err
	}
	if !wins(in, ver, updatedAt, curOrigin) {
		return nil
	}
	in.Version = ver + 1
	if in.UpdatedAt == 0 {
		in.UpdatedAt = time.Now().UnixMicro()
	}
	blob, err := encryptItem(kek, in)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`UPDATE items SET ciphertext = ?, type = ?, version = ?, updated_at = ?, deleted = 0, origin = ? WHERE id = ? AND user_id = ?`,
		blob, string(in.Type), in.Version, in.UpdatedAt, in.Origin, in.ID, userID,
	)
	return err
}

func wins(in Item, ver, updatedAt int64, origin string) bool {
	if in.Version != 0 && in.Version < ver {
		return false
	}
	if in.Version > ver {
		return true
	}
	if in.UpdatedAt != updatedAt {
		return in.UpdatedAt > updatedAt
	}
	return in.Origin > origin
}

func (s *Service) queryItems(ctx context.Context, kek []byte, q string, args ...any) ([]Item, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query items: %w", err)
	}
	defer rows.Close()
	var out []Item
	for rows.Next() {
		var (
			it   Item
			typ  string
			blob []byte
			del  int
		)
		if err := rows.Scan(&it.ID, &typ, &blob, &it.Version, &it.UpdatedAt, &del, &it.Origin); err != nil {
			return nil, err
		}
		it.Type = Type(typ)
		it.Deleted = del != 0
		if err := decryptItem(kek, blob, &it); err != nil {
			return nil, err
		}
		it.Binary = stripBinaryData(it.Binary)
		out = append(out, it)
	}
	return out, rows.Err()
}

// GetBinary возвращает запись вместе с телом файла.
func (s *Service) GetBinary(ctx context.Context, userID string, kek []byte, id string) (Item, error) {
	items, err := s.queryItemsFull(ctx, kek,
		`SELECT id, type, ciphertext, version, updated_at, deleted, origin FROM items WHERE user_id = ? AND id = ? AND deleted = 0`,
		userID, id,
	)
	if err != nil {
		return Item{}, err
	}
	if len(items) == 0 {
		return Item{}, ErrNotFound
	}
	return items[0], nil
}

func (s *Service) queryItemsFull(ctx context.Context, kek []byte, q string, args ...any) ([]Item, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Item
	for rows.Next() {
		var (
			it   Item
			typ  string
			blob []byte
			del  int
		)
		if err := rows.Scan(&it.ID, &typ, &blob, &it.Version, &it.UpdatedAt, &del, &it.Origin); err != nil {
			return nil, err
		}
		it.Type = Type(typ)
		it.Deleted = del != 0
		if err := decryptItem(kek, blob, &it); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

func encryptItem(kek []byte, in Item) ([]byte, error) {
	body := storedPayload{
		Metadata: in.Metadata,
		Login:    in.Login,
		Text:     in.Text,
		Binary:   in.Binary,
		Card:     in.Card,
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return cryptox.Seal(kek, raw)
}

func decryptItem(kek, blob []byte, it *Item) error {
	raw, err := cryptox.Open(kek, blob)
	if err != nil {
		return err
	}
	var body storedPayload
	if err := json.Unmarshal(raw, &body); err != nil {
		return fmt.Errorf("decode item: %w", err)
	}
	it.Metadata = body.Metadata
	it.Login = body.Login
	it.Text = body.Text
	it.Binary = body.Binary
	it.Card = body.Card
	return nil
}

func validate(in Item) error {
	if _, err := ParseType(string(in.Type)); err != nil {
		return err
	}
	switch in.Type {
	case TypeLogin:
		if in.Login == nil || in.Login.Username == "" {
			return ErrInvalidItem
		}
	case TypeText:
		if in.Text == nil || (in.Text.Title == "" && in.Text.Body == "") {
			return ErrInvalidItem
		}
	case TypeBinary:
		if in.Binary == nil || in.Binary.Filename == "" {
			return ErrInvalidItem
		}
		if len(in.Binary.Data) > maxBinary {
			return ErrTooLarge
		}
	case TypeCard:
		if in.Card == nil || in.Card.Number == "" {
			return ErrInvalidItem
		}
	}
	return nil
}

func stripBinaryData(b *BinaryPayload) *BinaryPayload {
	if b == nil {
		return nil
	}
	cp := *b
	if len(cp.Data) > 0 {
		cp.Data = nil
	}
	return &cp
}
