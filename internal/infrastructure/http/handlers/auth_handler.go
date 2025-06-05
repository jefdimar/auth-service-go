package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"auth-service-go/internal/application"
	"auth-service-go/internal/domain"
	"auth-service-go/pkg/logger"
)

// AuthHandler handles authentication HTTP requests
type AuthHandler struct {
	authService *application.AuthService
	logger      logger.Logger
}

// NewAuthHandler creates a new authentication handler
func NewAuthHandler(authService *application.AuthService) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		logger:      logger.GetLogger().WithField("component", "auth_handler"),
	}
}

// Register handles user registration
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	h.logger.Info("Processing registration request")

	var req domain.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.WithError(err).Warn("Invalid JSON in registration request")
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON format")
		return
	}

	response, err := h.authService.Register(&req)
	if err != nil {
		h.handleServiceError(w, err, "Registration failed")
		return
	}

	h.writeJSONResponse(w, http.StatusCreated, response)
	h.logger.WithField("user_id", response.User.ID).Info("User registered successfully")
}

// Login handles user login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	h.logger.Info("Processing login request")

	var req domain.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.WithError(err).Warn("Invalid JSON in login request")
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON format")
		return
	}

	response, err := h.authService.Login(&req)
	if err != nil {
		h.handleServiceError(w, err, "Login failed")
		return
	}

	h.writeJSONResponse(w, http.StatusOK, response)
	h.logger.WithField("user_id", response.User.ID).Info("User logged in successfully")
}

// RefreshToken handles token refresh
func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	h.logger.Info("Processing token refresh request")

	// Get token from Authorization header
	token := h.extractTokenFromHeader(r)
	if token == "" {
		h.logger.Warn("No token provided for refresh")
		h.writeErrorResponse(w, http.StatusUnauthorized, "Authorization token required")
		return
	}

	response, err := h.authService.RefreshToken(token)
	if err != nil {
		h.handleServiceError(w, err, "Token refresh failed")
		return
	}

	h.writeJSONResponse(w, http.StatusOK, response)
	h.logger.WithField("user_id", response.User.ID).Info("Token refreshed successfully")
}

// GetProfile handles getting user profile
func (h *AuthHandler) GetProfile(w http.ResponseWriter, r *http.Request) {
	h.logger.Info("Processing get profile request")

	// Get token from Authorization header
	token := h.extractTokenFromHeader(r)
	if token == "" {
		h.logger.Warn("No token provided for profile")
		h.writeErrorResponse(w, http.StatusUnauthorized, "Authorization token required")
		return
	}

	// Get user from token
	user, err := h.authService.GetUserByToken(token)
	if err != nil {
		h.handleServiceError(w, err, "Failed to get profile")
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"user": user,
	})
	h.logger.WithField("user_id", user.ID).Info("Profile retrieved successfully")
}

// UpdateProfile handles updating user profile
func (h *AuthHandler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	h.logger.Info("Processing update profile request")

	// Get token from Authorization header
	token := h.extractTokenFromHeader(r)
	if token == "" {
		h.logger.Warn("No token provided for profile update")
		h.writeErrorResponse(w, http.StatusUnauthorized, "Authorization token required")
		return
	}

	// Get user from token
	user, err := h.authService.GetUserByToken(token)
	if err != nil {
		h.handleServiceError(w, err, "Failed to authenticate user")
		return
	}

	// Parse update request
	var updates map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		h.logger.WithError(err).Warn("Invalid JSON in profile update request")
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON format")
		return
	}

	// Update profile
	updatedUser, err := h.authService.UpdateUserProfile(user.ID, updates)
	if err != nil {
		h.handleServiceError(w, err, "Failed to update profile")
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"user": updatedUser,
	})
	h.logger.WithField("user_id", updatedUser.ID).Info("Profile updated successfully")
}

// Logout handles user logout (client-side token invalidation)
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	h.logger.Info("Processing logout request")

	// For JWT tokens, logout is typically handled client-side by removing the token
	// We can log the event for audit purposes
	token := h.extractTokenFromHeader(r)
	if token != "" {
		user, err := h.authService.GetUserByToken(token)
		if err == nil {
			h.logger.WithField("user_id", user.ID).Info("User logged out")
		}
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]string{
		"message": "Logged out successfully",
	})
}

// extractTokenFromHeader extracts JWT token from Authorization header
func (h *AuthHandler) extractTokenFromHeader(r *http.Request) string {
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

// handleServiceError handles service layer errors and maps them to HTTP responses
func (h *AuthHandler) handleServiceError(w http.ResponseWriter, err error, context string) {
	h.logger.WithError(err).Error(context)

	switch err {
	case domain.ErrUserNotFound:
		h.writeErrorResponse(w, http.StatusNotFound, "User not found")
	case domain.ErrUserAlreadyExists:
		h.writeErrorResponse(w, http.StatusConflict, "User already exists")
	case domain.ErrInvalidCredentials:
		h.writeErrorResponse(w, http.StatusUnauthorized, "Invalid credentials")
	case domain.ErrInvalidToken:
		h.writeErrorResponse(w, http.StatusUnauthorized, "Invalid token")
	case domain.ErrTokenExpired:
		h.writeErrorResponse(w, http.StatusUnauthorized, "Token expired")
	case domain.ErrUnauthorized:
		h.writeErrorResponse(w, http.StatusUnauthorized, "Unauthorized")
	case domain.ErrForbidden:
		h.writeErrorResponse(w, http.StatusForbidden, "Forbidden")
	default:
		if strings.Contains(err.Error(), domain.ErrInvalidInput.Error()) {
			h.writeErrorResponse(w, http.StatusBadRequest, err.Error())
		} else {
			h.writeErrorResponse(w, http.StatusInternalServerError, "Internal server error")
		}
	}
}

// writeJSONResponse writes a JSON response
func (h *AuthHandler) writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.WithError(err).Error("Failed to encode JSON response")
	}
}

// writeErrorResponse writes an error response
func (h *AuthHandler) writeErrorResponse(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	errorResponse := map[string]interface{}{
		"error":   true,
		"message": message,
		"code":    statusCode,
	}

	if err := json.NewEncoder(w).Encode(errorResponse); err != nil {
		h.logger.WithError(err).Error("Failed to encode error response")
	}
}
