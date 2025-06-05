package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"auth-service-go/internal/application"
	"auth-service-go/internal/domain"
	"auth-service-go/pkg/logger"

	"github.com/gorilla/mux"
)

// AdminHandler handles admin-related HTTP requests
type AdminHandler struct {
	authService *application.AuthService
	logger      logger.Logger
}

// NewAdminHandler creates a new admin handler
func NewAdminHandler(authService *application.AuthService) *AdminHandler {
	return &AdminHandler{
		authService: authService,
		logger:      logger.GetLogger().WithField("component", "admin_handler"),
	}
}

// GetUsers handles getting all users (admin only)
func (h *AdminHandler) GetUsers(w http.ResponseWriter, r *http.Request) {
	h.logger.Info("Processing get users request")

	// Parse query parameters
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}

	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage < 1 || perPage > 100 {
		perPage = 10
	}

	offset := (page - 1) * perPage

	// Get users
	users, err := h.authService.GetAllUsers(offset, perPage)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get users")
		http.Error(w, "Failed to get users", http.StatusInternalServerError)
		return
	}

	// Get total count (you might want to add this method to your service)
	// For now, we'll use a placeholder
	total := len(users) // This is not accurate, but works for demo

	// Convert to response format
	userResponses := make([]*application.UserResponse, len(users))
	for i, user := range users {
		userResponses[i] = &application.UserResponse{
			ID:        user.ID,
			Email:     user.Email,
			FirstName: user.FirstName,
			LastName:  user.LastName,
			Role:      user.Role,
			IsActive:  user.IsActive,
			CreatedAt: user.CreatedAt,
			UpdatedAt: user.UpdatedAt,
		}
	}

	totalPages := (total + perPage - 1) / perPage

	response := &application.UsersListResponse{
		Users:      userResponses,
		Total:      total,
		Page:       page,
		PerPage:    perPage,
		TotalPages: totalPages,
	}

	h.logger.Info("Users retrieved successfully")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// GetUserByID handles getting a specific user by ID (admin only)
func (h *AdminHandler) GetUserByID(w http.ResponseWriter, r *http.Request) {
	h.logger.Info("Processing get user by ID request")

	vars := mux.Vars(r)
	userID := vars["id"]

	if userID == "" {
		h.logger.Error("User ID not provided")
		http.Error(w, "User ID is required", http.StatusBadRequest)
		return
	}

	// Get user profile
	user, err := h.authService.GetUserProfile(userID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get user profile")

		switch err {
		case domain.ErrUserNotFound:
			http.Error(w, "User not found", http.StatusNotFound)
		default:
			http.Error(w, "Failed to get user", http.StatusInternalServerError)
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

	h.logger.WithField("user_id", userID).Info("User profile retrieved successfully")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userResponse)
}

// UpdateUser handles updating a user (admin only)
func (h *AdminHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	h.logger.Info("Processing admin update user request")

	vars := mux.Vars(r)
	userID := vars["id"]

	if userID == "" {
		h.logger.Error("User ID not provided")
		http.Error(w, "User ID is required", http.StatusBadRequest)
		return
	}

	var req application.UpdateProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.WithError(err).Error("Failed to decode update user request")
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

	// Update user
	updatedUser, err := h.authService.UpdateUserProfile(userID, updates)
	if err != nil {
		h.logger.WithError(err).Error("Failed to update user")

		switch err {
		case domain.ErrUserNotFound:
			http.Error(w, "User not found", http.StatusNotFound)
		case domain.ErrUserAlreadyExists:
			http.Error(w, "Email already exists", http.StatusConflict)
		default:
			http.Error(w, "User update failed", http.StatusInternalServerError)
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

	h.logger.WithField("user_id", userID).Info("User updated successfully by admin")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userResponse)
}

// DeleteUser handles deleting a user (admin only)
func (h *AdminHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	h.logger.Info("Processing delete user request")

	vars := mux.Vars(r)
	userID := vars["id"]

	if userID == "" {
		h.logger.Error("User ID not provided")
		http.Error(w, "User ID is required", http.StatusBadRequest)
		return
	}

	// Delete user
	err := h.authService.DeleteUser(userID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to delete user")

		switch err {
		case domain.ErrUserNotFound:
			http.Error(w, "User not found", http.StatusNotFound)
		default:
			http.Error(w, "Failed to delete user", http.StatusInternalServerError)
		}
		return
	}

	h.logger.WithField("user_id", userID).Info("User deleted successfully")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "User has been permanently deleted",
		"user_id": userID,
	})
}

// GetStats handles getting user statistics (admin only)
func (h *AdminHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	h.logger.Info("Processing get stats request")

	// Get user statistics
	stats, err := h.authService.GetUserStats()
	if err != nil {
		h.logger.WithError(err).Error("Failed to get user statistics")
		http.Error(w, "Failed to get statistics", http.StatusInternalServerError)
		return
	}

	// Convert to response format (stats should already be in the right format)
	h.logger.Info("User statistics retrieved successfully")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// ToggleUserStatus handles activating/deactivating a user (admin only)
func (h *AdminHandler) ToggleUserStatus(w http.ResponseWriter, r *http.Request) {
	h.logger.Info("Processing toggle user status request")

	vars := mux.Vars(r)
	userID := vars["id"]

	if userID == "" {
		h.logger.Error("User ID not provided")
		http.Error(w, "User ID is required", http.StatusBadRequest)
		return
	}

	// Get current user
	user, err := h.authService.GetUserProfile(userID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get user for status toggle")

		switch err {
		case domain.ErrUserNotFound:
			http.Error(w, "User not found", http.StatusNotFound)
		default:
			http.Error(w, "Failed to get user", http.StatusInternalServerError)
		}
		return
	}

	// Toggle status
	updates := map[string]interface{}{
		"is_active": !user.IsActive,
	}

	// Note: You'll need to handle is_active in your UpdateUserProfile method
	updatedUser, err := h.authService.UpdateUserProfile(userID, updates)
	if err != nil {
		h.logger.WithError(err).Error("Failed to toggle user status")
		http.Error(w, "Failed to update user status", http.StatusInternalServerError)
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

	status := "activated"
	if !updatedUser.IsActive {
		status = "deactivated"
	}

	h.logger.WithFields(map[string]interface{}{
		"user_id": userID,
		"status":  status,
	}).Info("User status toggled successfully")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userResponse)
}
