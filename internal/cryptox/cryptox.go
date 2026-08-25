package cryptox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

// ErrInvalidCiphertext возвращается при повреждённом или поддельном блобе.
var ErrInvalidCiphertext = errors.New("invalid ciphertext")

const (
	kekTime    = 1
	kekMemory  = 32 * 1024
	kekThreads = 2
	kekLen     = 32
)

// DeriveKEK строит ключ шифрования хранилища из пароля и соли пользователя.
func DeriveKEK(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, kekTime, kekMemory, kekThreads, kekLen)
}

// NewSalt возвращает криптостойкую соль заданной длины.
func NewSalt(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("read salt: %w", err)
	}
	return b, nil
}

// Seal шифрует plaintext ключом 32 байта. Результат: nonce || ciphertext || tag.
func Seal(key, plaintext []byte) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce, err := NewSalt(aead.NonceSize())
	if err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Open расшифровывает блоб, полученный из Seal.
func Open(key, blob []byte) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	ns := aead.NonceSize()
	if len(blob) < ns {
		return nil, ErrInvalidCiphertext
	}
	plain, err := aead.Open(nil, blob[:ns], blob[ns:], nil)
	if err != nil {
		return nil, ErrInvalidCiphertext
	}
	return plain, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("aes key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	return aead, nil
}
