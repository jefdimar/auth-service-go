package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"auth-service-go/internal/application"
	"auth-service-go/internal/domain"
	"auth-service-go/pkg/logger"
)

// AuthHandler handles authentication-related HTTP requests
type AuthHandler struct {
	authService *application.AuthService
	logger      logger.Logger
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler(authService *application.AuthService) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		logger:      logger.GetLogger().WithField("component", "auth_handler"),
	}
}

// Register handles user registration
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	h.logger.Info("Processing user registration request")

	var req application.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.WithError(err).Error("Failed to decode registration request")
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Register user
	user, err := h.authService.Register(req.Email, req.Password, req.FirstName, req.LastName, req.Role)
	if err != nil {
		h.logger.WithError(err).Error("Failed to register user")

		switch err {
		case domain.ErrUserAlreadyExists:
			http.Error(w, "User already exists", http.StatusConflict)
		case domain.ErrInvalidInput:
			http.Error(w, err.Error(), http.StatusBadRequest)
		default:
			if err.Error() == "invalid input: invalid role" {
				http.Error(w, "Invalid role specified", http.StatusBadRequest)
			} else {
				http.Error(w, "Registration failed", http.StatusInternalServerError)
			}
		}
		return
	}

	// Convert to response format
	userResponse := &application.UserResponse{
		ID:        user.ID,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Role:      user.Role,
		IsActive:  user.IsActive,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}

	h.logger.WithField("user_id", user.ID).Info("User registered successfully")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "User registered successfully",
		"data":    userResponse,
	})
}

// Login handles user authentication
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	h.logger.Info("Processing login request")

	var req application.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.WithError(err).Error("Failed to decode login request")
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Authenticate user
	loginResponse, err := h.authService.Login(req.Email, req.Password)
	if err != nil {
		h.logger.WithError(err).Error("Login failed")

		switch err {
		case domain.ErrInvalidCredentials:
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		case domain.ErrUserInactive:
			http.Error(w, "Account is inactive", http.StatusForbidden)
		default:
			http.Error(w, "Login failed", http.StatusInternalServerError)
		}
		return
	}

	// Convert user to response format
	userResponse := &application.UserResponse{
		ID:        loginResponse.User.ID,
		Email:     loginResponse.User.Email,
		FirstName: loginResponse.User.FirstName,
		LastName:  loginResponse.User.LastName,
		Role:      loginResponse.User.Role,
		IsActive:  loginResponse.User.IsActive,
		CreatedAt: loginResponse.User.CreatedAt,
		UpdatedAt: loginResponse.User.UpdatedAt,
	}

	response := &application.LoginResponse{
		Token: loginResponse.Token,
		User:  userResponse,
	}

	h.logger.WithField("user_id", loginResponse.User.ID).Info("User logged in successfully")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Login successful",
		"data":    response,
	})
}

// GetProfile handles getting user profile
func (h *AuthHandler) GetProfile(w http.ResponseWriter, r *http.Request) {
	h.logger.Info("Processing get profile request")

	// Get user from context (set by auth middleware)
	user, ok := r.Context().Value("user").(*domain.User)
	if !ok {
		h.logger.Error("User not found in request context")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Convert to response format
	userResponse := &application.UserResponse{
		ID:        user.ID,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Role:      user.Role,
		IsActive:  user.IsActive,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}

	h.logger.WithField("user_id", user.ID).Info("Profile retrieved successfully")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Profile retrieved successfully",
		"data":    userResponse,
	})
}

// UpdateProfile handles updating user profile
func (h *AuthHandler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	h.logger.Info("Processing update profile request")

	// Get user from context
	user, ok := r.Context().Value("user").(*domain.User)
	if !ok {
		h.logger.Error("User not found in request context")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req application.UpdateProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.WithError(err).Error("Failed to decode update profile request")
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Convert request to updates map
	updates := make(map[string]interface{})
	if req.Email != "" {
		updates["email"] = req.Email
	}
	if req.FirstName != "" {
		updates["first_name"] = req.FirstName
	}
	if req.LastName != "" {
		updates["last_name"] = req.LastName
	}
	if req.Password != "" {
		updates["password"] = req.Password
	}

	// Update profile
	updatedUser, err := h.authService.UpdateUserProfile(user.ID, updates)
	if err != nil {
		h.logger.WithError(err).Error("Failed to update profile")

		switch err {
		case domain.ErrUserAlreadyExists:
			http.Error(w, "Email already exists", http.StatusConflict)
		case domain.ErrUserNotFound:
			http.Error(w, "User not found", http.StatusNotFound)
		default:
			http.Error(w, "Profile update failed", http.StatusInternalServerError)
		}
		return
	}

	// Convert to response format
	userResponse := &application.UserResponse{
		ID:        updatedUser.ID,
		Email:     updatedUser.Email,
		FirstName: updatedUser.FirstName,
		LastName:  updatedUser.LastName,
		Role:      updatedUser.Role,
		IsActive:  updatedUser.IsActive,
		CreatedAt: updatedUser.CreatedAt,
		UpdatedAt: updatedUser.UpdatedAt,
	}

	h.logger.WithField("user_id", user.ID).Info("Profile updated successfully")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Profile updated successfully",
		"data":    userResponse,
	})
}

// RefreshToken handles token refresh
func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	h.logger.Info("Processing token refresh request")

	// Get user from context
	user, ok := r.Context().Value("user").(*domain.User)
	if !ok {
		h.logger.Error("User not found in request context")
		h.writeErrorResponse(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// Generate new token
	token, err := h.authService.RefreshToken(user.ID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to refresh token")

		switch err {
		case domain.ErrUserNotFound:
			h.writeErrorResponse(w, http.StatusNotFound, "User not found")
		case domain.ErrUserInactive:
			h.writeErrorResponse(w, http.StatusForbidden, "Account is inactive")
		default:
			h.writeErrorResponse(w, http.StatusInternalServerError, "Token refresh failed")
		}
		return
	}

	response := map[string]string{
		"token": token,
	}

	h.logger.WithField("user_id", user.ID).Info("Token refreshed successfully")
	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"message": "Token refreshed successfully",
		"data":    response,
	})
}

// Logout handles user logout (token invalidation)
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	h.logger.Info("Processing logout request")

	// Get user from context
	user, ok := r.Context().Value("user").(*domain.User)
	if !ok {
		h.logger.Error("User not found in request context")
		h.writeErrorResponse(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// For JWT tokens, we can't really "invalidate" them server-side without a blacklist
	// For now, we'll just return success and let the client discard the token
	// In production, you might want to implement a token blacklist in Redis

	h.logger.WithField("user_id", user.ID).Info("User logged out successfully")
	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"message": "Logged out successfully",
		"data": map[string]string{
			"message": "Please discard your token on the client side",
		},
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
