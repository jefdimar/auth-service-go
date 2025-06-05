package application

import (
	"fmt"
	"strings"
	"time"

	"auth-service-go/internal/domain"
	"auth-service-go/pkg/jwt"
	"auth-service-go/pkg/logger"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// AuthService handles authentication operations
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

// RegisterUser registers a new user (alias for handler compatibility)
func (s *AuthService) Register(email, password, firstName, lastName, role string) (*domain.User, error) {
	return s.RegisterUser(email, password, firstName, lastName, role)
}

// RegisterUser registers a new user
func (s *AuthService) RegisterUser(email, password, firstName, lastName, role string) (*domain.User, error) {
	s.logger.WithFields(map[string]interface{}{
		"email": email,
		"role":  role,
	}).Info("Registering new user")

	// Validate input
	if email == "" || password == "" || firstName == "" || lastName == "" {
		return nil, fmt.Errorf("%w: all fields are required", domain.ErrInvalidInput)
	}

	// Validate role
	if role == "" {
		role = "user" // Default role
	}
	if !domain.IsValidRole(role) {
		return nil, fmt.Errorf("%w: invalid role", domain.ErrInvalidInput)
	}

	// Normalize email
	email = strings.ToLower(strings.TrimSpace(email))

	// Check if user already exists
	exists, err := s.userRepo.ExistsByEmail(email)
	if err != nil {
		s.logger.WithError(err).Error("Failed to check if user exists")
		return nil, fmt.Errorf("failed to check user existence: %w", err)
	}
	if exists {
		s.logger.WithField("email", email).Warn("Attempted to register existing user")
		return nil, domain.ErrUserAlreadyExists
	}

	// Hash password
	hashedPassword, err := s.hashPassword(password)
	if err != nil {
		s.logger.WithError(err).Error("Failed to hash password")
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user
	user := &domain.User{
		ID:        uuid.New().String(),
		Email:     email,
		Password:  hashedPassword,
		FirstName: strings.TrimSpace(firstName),
		LastName:  strings.TrimSpace(lastName),
		Role:      role,
		IsActive:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Save user
	if err := s.userRepo.Create(user); err != nil {
		s.logger.WithError(err).Error("Failed to create user")
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Clear password before returning
	user.Password = ""

	s.logger.WithFields(map[string]interface{}{
		"user_id": user.ID,
		"email":   user.Email,
	}).Info("User registered successfully")

	return user, nil
}

// Login authenticates a user and returns a JWT token (alias for handler compatibility)
func (s *AuthService) Login(email, password string) (*LoginResponse, error) {
	token, user, err := s.LoginUser(email, password)
	if err != nil {
		return nil, err
	}

	return &LoginResponse{
		Token: token,
		User: &UserResponse{
			ID:        user.ID,
			Email:     user.Email,
			FirstName: user.FirstName,
			LastName:  user.LastName,
			Role:      user.Role,
			IsActive:  user.IsActive,
			CreatedAt: user.CreatedAt,
			UpdatedAt: user.UpdatedAt,
		},
	}, nil
}

// LoginUser authenticates a user and returns a JWT token
func (s *AuthService) LoginUser(email, password string) (string, *domain.User, error) {
	s.logger.WithField("email", email).Info("User login attempt")

	// Validate input
	if email == "" || password == "" {
		return "", nil, fmt.Errorf("%w: email and password are required", domain.ErrInvalidInput)
	}

	// Normalize email
	email = strings.ToLower(strings.TrimSpace(email))

	// Get user by email
	user, err := s.userRepo.GetByEmail(email)
	if err != nil {
		if err == domain.ErrUserNotFound {
			s.logger.WithField("email", email).Warn("Login attempt with non-existent email")
			return "", nil, domain.ErrInvalidCredentials
		}
		s.logger.WithError(err).Error("Failed to get user by email")
		return "", nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Check if user is active
	if !user.IsActive {
		s.logger.WithField("user_id", user.ID).Warn("Login attempt for inactive user")
		return "", nil, domain.ErrUserInactive
	}

	// Verify password
	if !s.verifyPassword(password, user.Password) {
		s.logger.WithField("user_id", user.ID).Warn("Invalid password attempt")
		return "", nil, domain.ErrInvalidCredentials
	}

	// Generate JWT token
	token, err := s.jwtManager.GenerateToken(user.ID, user.Email, user.Role)
	if err != nil {
		s.logger.WithError(err).Error("Failed to generate JWT token")
		return "", nil, fmt.Errorf("failed to generate token: %w", err)
	}

	// Clear password before returning
	user.Password = ""

	s.logger.WithFields(map[string]interface{}{
		"user_id": user.ID,
		"email":   user.Email,
	}).Info("User logged in successfully")

	return token, user, nil
}

// GetUserByToken validates a JWT token and returns the user
func (s *AuthService) GetUserByToken(tokenString string) (*domain.User, error) {
	s.logger.Debug("Validating user token")

	// Validate token
	claims, err := s.jwtManager.ValidateToken(tokenString)
	if err != nil {
		s.logger.WithError(err).Debug("Token validation failed")
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	// Get user by ID
	user, err := s.userRepo.GetByID(claims.UserID)
	if err != nil {
		if err == domain.ErrUserNotFound {
			s.logger.WithField("user_id", claims.UserID).Warn("Token references non-existent user")
			return nil, domain.ErrUserNotFound
		}
		s.logger.WithError(err).Error("Failed to get user by ID")
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Check if user is still active
	if !user.IsActive {
		s.logger.WithField("user_id", user.ID).Warn("Token validation for inactive user")
		return nil, domain.ErrUserInactive
	}

	// Clear password
	user.Password = ""

	return user, nil
}

// GetUserProfile gets user profile by ID (alias for handler compatibility)
func (s *AuthService) GetUserProfile(userID string) (*domain.User, error) {
	return s.GetUserByID(userID)
}

// GetUserByID gets a user by ID
func (s *AuthService) GetUserByID(userID string) (*domain.User, error) {
	s.logger.WithField("user_id", userID).Debug("Getting user profile")

	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		if err == domain.ErrUserNotFound {
			return nil, domain.ErrUserNotFound
		}
		s.logger.WithError(err).Error("Failed to get user by ID")
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Clear password
	user.Password = ""
	return user, nil
}

// UpdateUserProfile updates a user's profile information (alias for handler compatibility)
func (s *AuthService) UpdateUserProfile(userID string, updates map[string]interface{}) (*domain.User, error) {
	return s.UpdateProfile(userID, updates)
}

// UpdateProfile updates a user's profile information
func (s *AuthService) UpdateProfile(userID string, updates map[string]interface{}) (*domain.User, error) {
	s.logger.WithField("user_id", userID).Info("Updating user profile")

	// Get existing user
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		if err == domain.ErrUserNotFound {
			return nil, domain.ErrUserNotFound
		}
		s.logger.WithError(err).Error("Failed to get user for profile update")
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

	// Handle password update
	if password, ok := updates["password"].(string); ok && password != "" {
		hashedPassword, err := s.hashPassword(password)
		if err != nil {
			return nil, fmt.Errorf("failed to hash password: %w", err)
		}
		user.Password = hashedPassword
	}

	user.UpdatedAt = time.Now()

	// Update user in database
	if err := s.userRepo.Update(user); err != nil {
		s.logger.WithError(err).Error("Failed to update user profile")
		return nil, fmt.Errorf("failed to update profile: %w", err)
	}

	// Clear password before returning
	user.Password = ""

	s.logger.WithField("user_id", userID).Info("User profile updated successfully")
	return user, nil
}

// RefreshToken generates a new token for a user
func (s *AuthService) RefreshToken(userID string) (string, error) {
	s.logger.WithField("user_id", userID).Info("Refreshing user token")

	// Get user
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		if err == domain.ErrUserNotFound {
			return "", domain.ErrUserNotFound
		}
		return "", fmt.Errorf("failed to get user: %w", err)
	}

	// Check if user is active
	if !user.IsActive {
		return "", domain.ErrUserInactive
	}

	// Generate new token
	token, err := s.jwtManager.GenerateToken(user.ID, user.Email, user.Role)
	if err != nil {
		s.logger.WithError(err).Error("Failed to generate refresh token")
		return "", fmt.Errorf("failed to generate token: %w", err)
	}

	s.logger.WithField("user_id", userID).Info("Token refreshed successfully")
	return token, nil
}

// GetAllUsers returns all users (for admin)
func (s *AuthService) GetAllUsers(offset, limit int) ([]*domain.User, error) {
	s.logger.WithFields(map[string]interface{}{
		"offset": offset,
		"limit":  limit,
	}).Info("Getting all users")

	users, err := s.userRepo.List(offset, limit)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get all users")
		return nil, fmt.Errorf("failed to get users: %w", err)
	}

	// Clear passwords
	for _, user := range users {
		user.Password = ""
	}

	return users, nil
}

// GetUserStats returns user statistics (for admin)
func (s *AuthService) GetUserStats() (map[string]interface{}, error) {
	s.logger.Info("Getting user statistics")

	stats, err := s.userRepo.GetStats()
	if err != nil {
		s.logger.WithError(err).Error("Failed to get user statistics")
		return nil, fmt.Errorf("failed to get user stats: %w", err)
	}

	return stats, nil
}

// hashPassword hashes a password using bcrypt
func (s *AuthService) hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// verifyPassword verifies a password against its hash
func (s *AuthService) verifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// DeleteUser deletes a user (admin only)
func (s *AuthService) DeleteUser(userID string) error {
	s.logger.WithField("user_id", userID).Info("Deleting user")

	// Check if user exists
	_, err := s.userRepo.GetByID(userID)
	if err != nil {
		if err == domain.ErrUserNotFound {
			return domain.ErrUserNotFound
		}
		s.logger.WithError(err).Error("Failed to get user for deletion")
		return fmt.Errorf("failed to get user: %w", err)
	}

	// Delete user
	if err := s.userRepo.Delete(userID); err != nil {
		s.logger.WithError(err).Error("Failed to delete user")
		return fmt.Errorf("failed to delete user: %w", err)
	}

	s.logger.WithField("user_id", userID).Info("User deleted successfully")
	return nil
}

// GetUserCount returns the total number of users
func (s *AuthService) GetUserCount() (int, error) {
	s.logger.Debug("Getting user count")

	count, err := s.userRepo.Count()
	if err != nil {
		s.logger.WithError(err).Error("Failed to get user count")
		return 0, fmt.Errorf("failed to get user count: %w", err)
	}

	return count, nil
}
