package utils

import (
	"context"
	"errors"

	"auth-service-go/internal/domain"
)

var (
	// ErrUserNotInContext is returned when user is not found in context
	ErrUserNotInContext = errors.New("user not found in context")
)

// GetUserFromContext extracts user from request context
func GetUserFromContext(ctx context.Context) (*domain.User, error) {
	user, ok := ctx.Value("user").(*domain.User)
	if !ok {
		return nil, ErrUserNotInContext
	}
	return user, nil
}

// GetUserIDFromContext extracts user ID from request context
func GetUserIDFromContext(ctx context.Context) (string, error) {
	userID, ok := ctx.Value("user_id").(string)
	if !ok {
		return "", ErrUserNotInContext
	}
	return userID, nil
}

// GetUserRoleFromContext extracts user role from request context
func GetUserRoleFromContext(ctx context.Context) (string, error) {
	role, ok := ctx.Value("user_role").(string)
	if !ok {
		return "", ErrUserNotInContext
	}
	return role, nil
}

// IsAdmin checks if the user in context is an admin
func IsAdmin(ctx context.Context) bool {
	role, err := GetUserRoleFromContext(ctx)
	if err != nil {
		return false
	}
	return role == string(domain.RoleAdmin)
}

// IsManager checks if the user in context is a manager
func IsManager(ctx context.Context) bool {
	role, err := GetUserRoleFromContext(ctx)
	if err != nil {
		return false
	}
	return role == string(domain.RoleManager)
}

// IsManagerOrAdmin checks if the user in context is a manager or admin
func IsManagerOrAdmin(ctx context.Context) bool {
	role, err := GetUserRoleFromContext(ctx)
	if err != nil {
		return false
	}
	return role == string(domain.RoleManager) || role == string(domain.RoleAdmin)
}

// HasRole checks if the user in context has a specific role
func HasRole(ctx context.Context, requiredRole domain.Role) bool {
	role, err := GetUserRoleFromContext(ctx)
	if err != nil {
		return false
	}

	userRole := domain.Role(role)
	// Admin has access to everything
	if userRole == domain.RoleAdmin {
		return true
	}

	return userRole == requiredRole
}
