package domain

import (
	"time"
)

// Role represents user roles in the system
type Role string

const (
	// RoleAdmin has full system access
	RoleAdmin Role = "admin"
	// RoleManager has limited administrative access
	RoleManager Role = "manager"
	// RoleUser has standard user access
	RoleUser Role = "user"
	// RoleViewer has read-only access
	RoleViewer Role = "viewer"
)

// User represents a user in the system
type User struct {
	ID        string    `json:"id" db:"id"`
	Email     string    `json:"email" db:"email"`
	Password  string    `json:"-" db:"password"` // Never include in JSON responses
	FirstName string    `json:"first_name" db:"first_name"`
	LastName  string    `json:"last_name" db:"last_name"`
	Role      string    `json:"role" db:"role"`
	IsActive  bool      `json:"is_active" db:"is_active"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// GetFullName returns the user's full name
func (u *User) GetFullName() string {
	return u.FirstName + " " + u.LastName
}

// HasRole checks if the user has a specific role
func (u *User) HasRole(role Role) bool {
	userRole := Role(u.Role)
	// Admin has access to everything
	if userRole == RoleAdmin {
		return true
	}
	return userRole == role
}

// IsAdmin checks if the user is an admin
func (u *User) IsAdmin() bool {
	return Role(u.Role) == RoleAdmin
}

// IsManager checks if the user is a manager
func (u *User) IsManager() bool {
	return Role(u.Role) == RoleManager
}

// IsManagerOrAdmin checks if the user is a manager or admin
func (u *User) IsManagerOrAdmin() bool {
	role := Role(u.Role)
	return role == RoleManager || role == RoleAdmin
}

// ValidRoles returns a slice of all valid roles
func ValidRoles() []Role {
	return []Role{RoleAdmin, RoleManager, RoleUser, RoleViewer}
}

// IsValidRole checks if a role string is valid
func IsValidRole(role string) bool {
	validRoles := ValidRoles()
	for _, validRole := range validRoles {
		if string(validRole) == role {
			return true
		}
	}
	return false
}
