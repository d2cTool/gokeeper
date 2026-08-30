package auth

import "errors"

// Ошибки домена аутентификации.
var (
	ErrInvalidCredentials = errors.New("invalid login or password")
	ErrLoginTaken         = errors.New("login already taken")
	ErrInvalidToken       = errors.New("invalid or expired token")
	ErrSessionExpired     = errors.New("session expired")
	ErrWeakPassword       = errors.New("password must be at least 8 characters")
	ErrEmptyLogin         = errors.New("login is required")
)
