package domain

import "errors"

// Domain errors
var (
	// User errors
	ErrUserNotFound       = errors.New("user not found")
	ErrUserAlreadyExists  = errors.New("user already exists")
	ErrInvalidCredentials = errors.New("invalid credentials")

	// Authentication errors
	ErrInvalidToken = errors.New("invalid token")
	ErrTokenExpired = errors.New("token expired")
	ErrUnauthorized = errors.New("unauthorized")
	ErrForbidden    = errors.New("forbidden")

	// Input validation errors
	ErrInvalidInput     = errors.New("invalid input")
	ErrValidationFailed = errors.New("validation failed")

	// General errors
	ErrInternalServer = errors.New("internal server error")
	ErrNotImplemented = errors.New("not implemented")
)
