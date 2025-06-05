package domain

import "errors"

// Domain errors
var (
	// ErrUserNotFound is returned when a user is not found
	ErrUserNotFound = errors.New("user not found")

	// ErrUserAlreadyExists is returned when trying to create a user that already exists
	ErrUserAlreadyExists = errors.New("user already exists")

	// ErrInvalidCredentials is returned when login credentials are invalid
	ErrInvalidCredentials = errors.New("invalid credentials")

	// Authentication errors
	ErrInvalidToken = errors.New("invalid token")
	ErrTokenExpired = errors.New("token expired")

	// ErrUnauthorized is returned when user lacks permission
	ErrUnauthorized = errors.New("unauthorized")

	// ErrForbidden is returned when user is forbidden from accessing resource
	ErrForbidden = errors.New("forbidden")

	// Input validation errors
	ErrInvalidInput     = errors.New("invalid input")
	ErrValidationFailed = errors.New("validation failed")

	// ErrUserInactive is returned when trying to authenticate an inactive user
	ErrUserInactive = errors.New("user account is inactive")

	// General errors
	ErrInternalServer = errors.New("internal server error")
	ErrNotImplemented = errors.New("not implemented")
)
