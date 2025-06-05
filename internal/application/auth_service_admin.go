package application

import (
	"fmt"
	"strings"
	"time"

	"auth-service-go/internal/domain"
)

// ListUsers returns a paginated list of users (admin only)
func (s *AuthService) ListUsers(offset, limit int) ([]*domain.User, int, error) {
	s.logger.WithFields(map[string]interface{}{
		"offset": offset,
		"limit":  limit,
	}).Info("Listing users")

	users, err := s.userRepo.List(offset, limit)
	if err != nil {
		s.logger.WithError(err).Error("Failed to list users")
		return nil, 0, fmt.Errorf("failed to list users: %w", err)
	}

	// Clear passwords
	for _, user := range users {
		user.Password = ""
	}

	// Get total count
	total, err := s.userRepo.Count()
	if err != nil {
		s.logger.WithError(err).Error("Failed to count users")
		return nil, 0, fmt.Errorf("failed to count users: %w", err)
	}

	s.logger.WithFields(map[string]interface{}{
		"count": len(users),
		"total": total,
	}).Info("Users listed successfully")

	return users, total, nil
}

// AdminUpdateUser updates a user with admin privileges (can update role, active status, etc.)
func (s *AuthService) AdminUpdateUser(userID string, updates map[string]interface{}) (*domain.User, error) {
	s.logger.WithField("user_id", userID).Info("Admin updating user")

	// Get existing user
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		if err == domain.ErrUserNotFound {
			return nil, domain.ErrUserNotFound
		}
		s.logger.WithError(err).Error("Failed to get user for admin update")
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

	// Admin can update role
	if role, ok := updates["role"].(string); ok && role != "" {
		if domain.IsValidRole(role) {
			user.Role = role
		} else {
			return nil, fmt.Errorf("%w: invalid role", domain.ErrInvalidInput)
		}
	}

	// Admin can update active status
	if isActive, ok := updates["is_active"].(bool); ok {
		user.IsActive = isActive
	}

	user.UpdatedAt = time.Now()

	// Update user in database
	if err := s.userRepo.Update(user); err != nil {
		s.logger.WithError(err).Error("Failed to admin update user")
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	// Clear password before returning
	user.Password = ""

	s.logger.WithField("user_id", userID).Info("User updated by admin successfully")
	return user, nil
}

// DeactivateUser deactivates a user account
func (s *AuthService) DeactivateUser(userID string) error {
	s.logger.WithField("user_id", userID).Info("Deactivating user")

	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		if err == domain.ErrUserNotFound {
			return domain.ErrUserNotFound
		}
		return fmt.Errorf("failed to get user: %w", err)
	}

	user.IsActive = false
	user.UpdatedAt = time.Now()

	if err := s.userRepo.Update(user); err != nil {
		s.logger.WithError(err).Error("Failed to deactivate user")
		return fmt.Errorf("failed to deactivate user: %w", err)
	}

	s.logger.WithField("user_id", userID).Info("User deactivated successfully")
	return nil
}

// ActivateUser activates a user account
func (s *AuthService) ActivateUser(userID string) error {
	s.logger.WithField("user_id", userID).Info("Activating user")

	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		if err == domain.ErrUserNotFound {
			return domain.ErrUserNotFound
		}
		return fmt.Errorf("failed to get user: %w", err)
	}

	user.IsActive = true
	user.UpdatedAt = time.Now()

	if err := s.userRepo.Update(user); err != nil {
		s.logger.WithError(err).Error("Failed to activate user")
		return fmt.Errorf("failed to activate user: %w", err)
	}

	s.logger.WithField("user_id", userID).Info("User activated successfully")
	return nil
}

// DeleteUser deletes a user account
func (s *AuthService) DeleteUserAdmin(userID string) error {
	s.logger.WithField("user_id", userID).Info("Deleting user")

	if err := s.userRepo.Delete(userID); err != nil {
		if err == domain.ErrUserNotFound {
			return domain.ErrUserNotFound
		}
		s.logger.WithError(err).Error("Failed to delete user")
		return fmt.Errorf("failed to delete user: %w", err)
	}

	s.logger.WithField("user_id", userID).Info("User deleted successfully")
	return nil
}
