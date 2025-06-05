package application

import (
	"fmt"
	"strings"
	"time"

	"auth-service-go/internal/domain"
	"auth-service-go/pkg/jwt"
	"auth-service-go/pkg/logger"

	"github.com/google/uuid"
)

// AuthService handles authentication business logic
type AuthService struct {
	userRepo   domain.UserRepository
	jwtManager *jwt.JWTManager
	logger     logger.Logger
}

// NewAuthService creates a new authentication service
func NewAuthService(userRepo domain.UserRepository, jwtManager *jwt.JWTManager) *AuthService {
	return &AuthService{
		userRepo:   userRepo,
		jwtManager: jwtManager,
		logger:     logger.GetLogger().WithField("component", "auth_service"),
	}
}

// Register creates a new user account
func (s *AuthService) Register(req *domain.RegisterRequest) (*domain.AuthResponse, error) {
	s.logger.WithField("email", req.Email).Info("Processing user registration")

	// Validate input
	if err := s.validateRegisterRequest(req); err != nil {
		s.logger.WithError(err).Warn("Invalid registration request")
		return nil, err
	}

	// Check if user already exists
	exists, err := s.userRepo.ExistsByEmail(req.Email)
	if err != nil {
		s.logger.WithError(err).Error("Failed to check user existence")
		return nil, fmt.Errorf("failed to check user existence: %w", err)
	}

	if exists {
		s.logger.WithField("email", req.Email).Warn("User already exists")
		return nil, domain.ErrUserAlreadyExists
	}

	// Create user
	user := &domain.User{
		ID:        uuid.New().String(),
		Email:     strings.ToLower(strings.TrimSpace(req.Email)),
		Password:  req.Password, // Will be hashed in repository
		FirstName: strings.TrimSpace(req.FirstName),
		LastName:  strings.TrimSpace(req.LastName),
		Role:      s.getDefaultRole(req.Role),
		IsActive:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Save user to database
	if err := s.userRepo.Create(user); err != nil {
		s.logger.WithError(err).Error("Failed to create user")
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Generate JWT token
	token, expiresAt, err := s.jwtManager.GenerateToken(user)
	if err != nil {
		s.logger.WithError(err).Error("Failed to generate token for new user")
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	// Clear password before returning
	user.Password = ""

	response := &domain.AuthResponse{
		Token:     token,
		User:      user,
		ExpiresAt: expiresAt,
	}

	s.logger.WithFields(map[string]interface{}{
		"user_id": user.ID,
		"email":   user.Email,
	}).Info("User registered successfully")

	return response, nil
}

// Login authenticates a user and returns a token
func (s *AuthService) Login(req *domain.LoginRequest) (*domain.AuthResponse, error) {
	s.logger.WithField("email", req.Email).Info("Processing user login")

	// Validate input
	if err := s.validateLoginRequest(req); err != nil {
		s.logger.WithError(err).Warn("Invalid login request")
		return nil, err
	}

	// Get user by email
	user, err := s.userRepo.GetByEmail(strings.ToLower(strings.TrimSpace(req.Email)))
	if err != nil {
		if err == domain.ErrUserNotFound {
			s.logger.WithField("email", req.Email).Warn("Login attempt with non-existent email")
			return nil, domain.ErrInvalidCredentials
		}
		s.logger.WithError(err).Error("Failed to get user by email")
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Check if user is active
	if !user.IsActive {
		s.logger.WithField("user_id", user.ID).Warn("Login attempt for inactive user")
		return nil, domain.ErrInvalidCredentials
	}

	// Verify password
	if !user.CheckPassword(req.Password) {
		s.logger.WithField("user_id", user.ID).Warn("Invalid password attempt")
		return nil, domain.ErrInvalidCredentials
	}

	// Generate JWT token
	token, expiresAt, err := s.jwtManager.GenerateToken(user)
	if err != nil {
		s.logger.WithError(err).Error("Failed to generate token for login")
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	// Clear password before returning
	user.Password = ""

	response := &domain.AuthResponse{
		Token:     token,
		User:      user,
		ExpiresAt: expiresAt,
	}

	s.logger.WithFields(map[string]interface{}{
		"user_id": user.ID,
		"email":   user.Email,
	}).Info("User logged in successfully")

	return response, nil
}

// GetUserByToken validates a token and returns the user
func (s *AuthService) GetUserByToken(tokenString string) (*domain.User, error) {
	s.logger.Debug("Getting user by token")

	// Validate token
	claims, err := s.jwtManager.ValidateToken(tokenString)
	if err != nil {
		s.logger.WithError(err).Warn("Invalid token provided")
		return nil, domain.ErrInvalidToken
	}

	// Get user by ID
	user, err := s.userRepo.GetByID(claims.UserID)
	if err != nil {
		if err == domain.ErrUserNotFound {
			s.logger.WithField("user_id", claims.UserID).Warn("Token valid but user not found")
			return nil, domain.ErrInvalidToken
		}
		s.logger.WithError(err).Error("Failed to get user by ID from token")
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Check if user is still active
	if !user.IsActive {
		s.logger.WithField("user_id", user.ID).Warn("Token valid but user is inactive")
		return nil, domain.ErrUnauthorized
	}

	// Clear password
	user.Password = ""

	return user, nil
}

// RefreshToken refreshes a JWT token
func (s *AuthService) RefreshToken(tokenString string) (*domain.AuthResponse, error) {
	s.logger.Debug("Refreshing token")

	// Get user from current token
	user, err := s.GetUserByToken(tokenString)
	if err != nil {
		return nil, err
	}

	// Generate new token
	newToken, expiresAt, err := s.jwtManager.GenerateToken(user)
	if err != nil {
		s.logger.WithError(err).Error("Failed to generate refreshed token")
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	response := &domain.AuthResponse{
		Token:     newToken,
		User:      user,
		ExpiresAt: expiresAt,
	}

	s.logger.WithField("user_id", user.ID).Info("Token refreshed successfully")
	return response, nil
}

// validateRegisterRequest validates registration request
func (s *AuthService) validateRegisterRequest(req *domain.RegisterRequest) error {
	if req.Email == "" {
		return fmt.Errorf("%w: email is required", domain.ErrInvalidInput)
	}

	if req.Password == "" {
		return fmt.Errorf("%w: password is required", domain.ErrInvalidInput)
	}

	if len(req.Password) < 6 {
		return fmt.Errorf("%w: password must be at least 6 characters", domain.ErrInvalidInput)
	}

	if req.FirstName == "" {
		return fmt.Errorf("%w: first name is required", domain.ErrInvalidInput)
	}

	if req.LastName == "" {
		return fmt.Errorf("%w: last name is required", domain.ErrInvalidInput)
	}

	// Basic email validation
	if !strings.Contains(req.Email, "@") {
		return fmt.Errorf("%w: invalid email format", domain.ErrInvalidInput)
	}

	return nil
}

// validateLoginRequest validates login request
func (s *AuthService) validateLoginRequest(req *domain.LoginRequest) error {
	if req.Email == "" {
		return fmt.Errorf("%w: email is required", domain.ErrInvalidInput)
	}

	if req.Password == "" {
		return fmt.Errorf("%w: password is required", domain.ErrInvalidInput)
	}

	return nil
}

// getDefaultRole returns the default role for a user
func (s *AuthService) getDefaultRole(requestedRole string) string {
	// If no role specified, default to user
	if requestedRole == "" {
		return string(domain.RoleUser)
	}

	// Validate requested role
	switch requestedRole {
	case string(domain.RoleUser), string(domain.RoleManager), string(domain.RoleViewer):
		return requestedRole
	case string(domain.RoleAdmin):
		// Admin role can only be assigned manually, default to user
		s.logger.Warn("Admin role requested during registration, defaulting to user")
		return string(domain.RoleUser)
	default:
		s.logger.WithField("role", requestedRole).Warn("Invalid role requested, defaulting to user")
		return string(domain.RoleUser)
	}
}

// GetUserProfile gets user profile by ID
func (s *AuthService) GetUserProfile(userID string) (*domain.User, error) {
	s.logger.WithField("user_id", userID).Debug("Getting user profile")

	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		if err == domain.ErrUserNotFound {
			return nil, domain.ErrUserNotFound
		}
		s.logger.WithError(err).Error("Failed to get user profile")
		return nil, fmt.Errorf("failed to get user profile: %w", err)
	}

	// Clear password
	user.Password = ""

	return user, nil
}

// UpdateUserProfile updates user profile
func (s *AuthService) UpdateUserProfile(userID string, updates map[string]interface{}) (*domain.User, error) {
	s.logger.WithField("user_id", userID).Info("Updating user profile")

	// Get existing user
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		if err == domain.ErrUserNotFound {
			return nil, domain.ErrUserNotFound
		}
		s.logger.WithError(err).Error("Failed to get user for update")
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Apply updates
	if firstName, ok := updates["first_name"].(string); ok && firstName != "" {
		user.FirstName = strings.TrimSpace(firstName)
	}

	if lastName, ok := updates["last_name"].(string); ok && lastName != "" {
		user.LastName = strings.TrimSpace(lastName)
	}

	if email, ok := updates["email"].(string); ok && email != "" {
		email = strings.ToLower(strings.TrimSpace(email))
		if email != user.Email {
			// Check if new email already exists
			exists, err := s.userRepo.ExistsByEmail(email)
			if err != nil {
				return nil, fmt.Errorf("failed to check email existence: %w", err)
			}
			if exists {
				return nil, domain.ErrUserAlreadyExists
			}
			user.Email = email
		}
	}

	// Update user in database
	if err := s.userRepo.Update(user); err != nil {
		s.logger.WithError(err).Error("Failed to update user profile")
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	// Clear password before returning
	user.Password = ""

	s.logger.WithField("user_id", userID).Info("User profile updated successfully")
	return user, nil
}
