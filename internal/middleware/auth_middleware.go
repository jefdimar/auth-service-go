package middleware

import (
	"context"
	"net/http"
	"strings"

	"auth-service-go/internal/application"
	"auth-service-go/internal/domain"
	httputils "auth-service-go/internal/infrastructure/http"
	"auth-service-go/pkg/logger"
)

// AuthMiddleware handles authentication and authorization
type AuthMiddleware struct {
	authService *application.AuthService
	logger      logger.Logger
}

// NewAuthMiddleware creates a new auth middleware
func NewAuthMiddleware(authService *application.AuthService) *AuthMiddleware {
	return &AuthMiddleware{
		authService: authService,
		logger:      logger.GetLogger().WithField("component", "auth_middleware"),
	}
}

// RequireAuth middleware that requires valid authentication
func (m *AuthMiddleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.logger.Debug("Checking authentication")

		// Get token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			m.logger.Debug("Missing Authorization header")
			httputils.WriteUnauthorizedError(w, "Authorization header required")
			return
		}

		// Extract token from "Bearer <token>" format
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			m.logger.Debug("Invalid Authorization header format")
			httputils.WriteUnauthorizedError(w, "Invalid authorization header format")
			return
		}

		token := parts[1]
		if token == "" {
			m.logger.Debug("Empty token")
			httputils.WriteUnauthorizedError(w, "Token required")
			return
		}

		// Validate token and get user
		user, err := m.authService.GetUserByToken(token)
		if err != nil {
			m.logger.WithError(err).Debug("Token validation failed")
			httputils.WriteUnauthorizedError(w, "Invalid or expired token")
			return
		}

		// Add user to request context
		ctx := context.WithValue(r.Context(), "user", user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireAdmin middleware that requires admin role
func (m *AuthMiddleware) RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.logger.Debug("Checking admin authorization")

		user, ok := r.Context().Value("user").(*domain.User)
		if !ok {
			m.logger.Error("User not found in context")
			httputils.WriteUnauthorizedError(w, "Authentication required")
			return
		}

		if !user.IsAdmin() {
			m.logger.WithFields(map[string]interface{}{
				"user_id": user.ID,
				"role":    user.Role,
			}).Warn("Access denied: admin role required")
			http.Error(w, "Admin access required", http.StatusForbidden)
			return
		}

		m.logger.WithField("user_id", user.ID).Debug("Admin access granted")
		next.ServeHTTP(w, r)
	})
}

// RequireManagerOrAdmin middleware that requires manager or admin role
func (m *AuthMiddleware) RequireManagerOrAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.logger.Debug("Checking manager/admin authorization")

		user, ok := r.Context().Value("user").(*domain.User)
		if !ok {
			m.logger.Error("User not found in context")
			httputils.WriteUnauthorizedError(w, "Authentication required")
			return
		}

		if !user.IsManagerOrAdmin() {
			m.logger.WithFields(map[string]interface{}{
				"user_id": user.ID,
				"role":    user.Role,
			}).Warn("Access denied: manager or admin role required")
			http.Error(w, "Manager or admin access required", http.StatusForbidden)
			return
		}

		m.logger.WithField("user_id", user.ID).Debug("Manager/admin access granted")
		next.ServeHTTP(w, r)
	})
}

// RequireRole middleware that requires a specific role
func (m *AuthMiddleware) RequireRole(requiredRole domain.Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			m.logger.WithField("required_role", requiredRole).Debug("Checking role authorization")

			user, ok := r.Context().Value("user").(*domain.User)
			if !ok {
				m.logger.Error("User not found in context")
				httputils.WriteUnauthorizedError(w, "Authentication required")
				return
			}

			if !user.HasRole(requiredRole) {
				m.logger.WithFields(map[string]interface{}{
					"user_id":       user.ID,
					"user_role":     user.Role,
					"required_role": requiredRole,
				}).Warn("Access denied: insufficient role")
				http.Error(w, "Insufficient permissions", http.StatusForbidden)
				return
			}

			m.logger.WithFields(map[string]interface{}{
				"user_id": user.ID,
				"role":    user.Role,
			}).Debug("Role access granted")
			next.ServeHTTP(w, r)
		})
	}
}

// OptionalAuth middleware that optionally authenticates (doesn't fail if no token)
func (m *AuthMiddleware) OptionalAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := m.extractTokenFromHeader(r)
		if token == "" {
			// No token provided, continue without authentication
			next.ServeHTTP(w, r)
			return
		}

		// Try to authenticate
		user, err := m.authService.GetUserByToken(token)
		if err != nil {
			// Invalid token, but don't fail - just continue without authentication
			m.logger.WithError(err).Debug("Optional auth failed, continuing without authentication")
			next.ServeHTTP(w, r)
			return
		}

		// Add user to context
		ctx := context.WithValue(r.Context(), "user", user)
		ctx = context.WithValue(ctx, "user_id", user.ID)
		ctx = context.WithValue(ctx, "user_role", user.Role)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// extractTokenFromHeader extracts JWT token from Authorization header
func (m *AuthMiddleware) extractTokenFromHeader(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}

	// Expected format: "Bearer <token>"
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return ""
	}

	return parts[1]
}

// handleAuthError handles authentication errors
func (m *AuthMiddleware) handleAuthError(w http.ResponseWriter, err error) {
	switch err {
	case domain.ErrInvalidToken:
		httputils.WriteUnauthorizedError(w, "Invalid token")
	case domain.ErrTokenExpired:
		httputils.WriteUnauthorizedError(w, "Token expired")
	case domain.ErrUnauthorized:
		httputils.WriteUnauthorizedError(w, "Unauthorized")
	default:
		httputils.WriteUnauthorizedError(w, "Authentication failed")
	}
}
