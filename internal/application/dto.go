package application

import "time"

// RegisterRequest represents a user registration request
type RegisterRequest struct {
	Email     string `json:"email" validate:"required,email"`
	Password  string `json:"password" validate:"required,min=8"`
	FirstName string `json:"first_name" validate:"required"`
	LastName  string `json:"last_name" validate:"required"`
	Role      string `json:"role,omitempty"`
}

// LoginRequest represents a user login request
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// UpdateProfileRequest represents a profile update request
type UpdateProfileRequest struct {
	Email     string `json:"email,omitempty" validate:"omitempty,email"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
	Password  string `json:"password,omitempty" validate:"omitempty,min=8"`
}

// UserResponse represents a user in API responses
type UserResponse struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	Role      string    `json:"role"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// LoginResponse represents the login response
type LoginResponse struct {
	Token string        `json:"token"`
	User  *UserResponse `json:"user"`
}

// UsersListResponse represents a paginated list of users
type UsersListResponse struct {
	Users      []*UserResponse `json:"users"`
	Total      int             `json:"total"`
	Page       int             `json:"page"`
	PerPage    int             `json:"per_page"`
	TotalPages int             `json:"total_pages"`
}

// StatsResponse represents user statistics
type StatsResponse struct {
	TotalUsers          int            `json:"total_users"`
	ActiveUsers         int            `json:"active_users"`
	InactiveUsers       int            `json:"inactive_users"`
	RecentRegistrations int            `json:"recent_registrations"`
	UsersByRole         map[string]int `json:"users_by_role"`
}
