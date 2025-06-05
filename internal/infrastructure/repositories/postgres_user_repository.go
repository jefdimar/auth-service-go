package repositories

import (
	"database/sql"
	"fmt"
	"time"

	"auth-service-go/internal/domain"
	"auth-service-go/pkg/logger"

	"github.com/lib/pq"
)

// PostgresUserRepository implements UserRepository using PostgreSQL
type PostgresUserRepository struct {
	db     *sql.DB
	logger logger.Logger
}

// NewPostgresUserRepository creates a new PostgreSQL user repository
func NewPostgresUserRepository(db *sql.DB) domain.UserRepository {
	return &PostgresUserRepository{
		db:     db,
		logger: logger.GetLogger().WithField("component", "postgres_user_repository"),
	}
}

// Create creates a new user
func (r *PostgresUserRepository) Create(user *domain.User) error {
	r.logger.WithField("email", user.Email).Info("Creating user")

	query := `
		INSERT INTO users (id, email, password, first_name, last_name, role, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`

	_, err := r.db.Exec(query,
		user.ID,
		user.Email,
		user.Password, // Password should already be hashed by the service
		user.FirstName,
		user.LastName,
		user.Role,
		user.IsActive,
		user.CreatedAt,
		user.UpdatedAt,
	)

	if err != nil {
		// Check for unique constraint violation (duplicate email)
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			r.logger.WithField("email", user.Email).Warn("Attempted to create user with duplicate email")
			return domain.ErrUserAlreadyExists
		}
		r.logger.WithError(err).Error("Failed to create user")
		return fmt.Errorf("failed to create user: %w", err)
	}

	r.logger.WithField("user_id", user.ID).Info("User created successfully")
	return nil
}

// GetByID retrieves a user by ID
func (r *PostgresUserRepository) GetByID(id string) (*domain.User, error) {
	r.logger.WithField("user_id", id).Debug("Getting user by ID")

	query := `
		SELECT id, email, password, first_name, last_name, role, is_active, created_at, updated_at
		FROM users
		WHERE id = $1
	`

	user := &domain.User{}
	err := r.db.QueryRow(query, id).Scan(
		&user.ID,
		&user.Email,
		&user.Password,
		&user.FirstName,
		&user.LastName,
		&user.Role,
		&user.IsActive,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			r.logger.WithField("user_id", id).Debug("User not found")
			return nil, domain.ErrUserNotFound
		}
		r.logger.WithError(err).Error("Failed to get user by ID")
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return user, nil
}

// GetByEmail retrieves a user by email
func (r *PostgresUserRepository) GetByEmail(email string) (*domain.User, error) {
	r.logger.WithField("email", email).Debug("Getting user by email")

	query := `
		SELECT id, email, password, first_name, last_name, role, is_active, created_at, updated_at
		FROM users
		WHERE email = $1
	`

	user := &domain.User{}
	err := r.db.QueryRow(query, email).Scan(
		&user.ID,
		&user.Email,
		&user.Password,
		&user.FirstName,
		&user.LastName,
		&user.Role,
		&user.IsActive,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			r.logger.WithField("email", email).Debug("User not found")
			return nil, domain.ErrUserNotFound
		}
		r.logger.WithError(err).Error("Failed to get user by email")
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return user, nil
}

// Update updates an existing user
func (r *PostgresUserRepository) Update(user *domain.User) error {
	r.logger.WithField("user_id", user.ID).Info("Updating user")

	user.UpdatedAt = time.Now()

	query := `
		UPDATE users
		SET email = $2, password = $3, first_name = $4, last_name = $5, role = $6, is_active = $7, updated_at = $8
		WHERE id = $1
	`

	result, err := r.db.Exec(query,
		user.ID,
		user.Email,
		user.Password,
		user.FirstName,
		user.LastName,
		user.Role,
		user.IsActive,
		user.UpdatedAt,
	)

	if err != nil {
		// Check for unique constraint violation (duplicate email)
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			r.logger.WithField("email", user.Email).Warn("Attempted to update user with duplicate email")
			return domain.ErrUserAlreadyExists
		}
		r.logger.WithError(err).Error("Failed to update user")
		return fmt.Errorf("failed to update user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		r.logger.WithError(err).Error("Failed to get rows affected")
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		r.logger.WithField("user_id", user.ID).Warn("No rows affected during update")
		return domain.ErrUserNotFound
	}

	r.logger.WithField("user_id", user.ID).Info("User updated successfully")
	return nil
}

// Delete deletes a user by ID
func (r *PostgresUserRepository) Delete(id string) error {
	r.logger.WithField("user_id", id).Info("Deleting user")

	query := `DELETE FROM users WHERE id = $1`

	result, err := r.db.Exec(query, id)
	if err != nil {
		r.logger.WithError(err).Error("Failed to delete user")
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		r.logger.WithError(err).Error("Failed to get rows affected")
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		r.logger.WithField("user_id", id).Warn("No rows affected during delete")
		return domain.ErrUserNotFound
	}

	r.logger.WithField("user_id", id).Info("User deleted successfully")
	return nil
}

// ExistsByEmail checks if a user exists by email
func (r *PostgresUserRepository) ExistsByEmail(email string) (bool, error) {
	r.logger.WithField("email", email).Debug("Checking if user exists by email")

	query := `SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)`

	var exists bool
	err := r.db.QueryRow(query, email).Scan(&exists)
	if err != nil {
		r.logger.WithError(err).Error("Failed to check if user exists")
		return false, fmt.Errorf("failed to check user existence: %w", err)
	}

	return exists, nil
}

// List returns a paginated list of users
func (r *PostgresUserRepository) List(offset, limit int) ([]*domain.User, error) {
	r.logger.WithFields(map[string]interface{}{
		"offset": offset,
		"limit":  limit,
	}).Debug("Listing users")

	query := `
		SELECT id, email, password, first_name, last_name, role, is_active, created_at, updated_at
		FROM users
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`

	rows, err := r.db.Query(query, limit, offset)
	if err != nil {
		r.logger.WithError(err).Error("Failed to list users")
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	defer rows.Close()

	var users []*domain.User
	for rows.Next() {
		user := &domain.User{}
		err := rows.Scan(
			&user.ID,
			&user.Email,
			&user.Password,
			&user.FirstName,
			&user.LastName,
			&user.Role,
			&user.IsActive,
			&user.CreatedAt,
			&user.UpdatedAt,
		)
		if err != nil {
			r.logger.WithError(err).Error("Failed to scan user row")
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}
		users = append(users, user)
	}

	if err = rows.Err(); err != nil {
		r.logger.WithError(err).Error("Error iterating user rows")
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}

	r.logger.WithField("count", len(users)).Debug("Users listed successfully")
	return users, nil
}

// Count returns the total number of users
func (r *PostgresUserRepository) Count() (int, error) {
	r.logger.Debug("Counting users")

	query := `SELECT COUNT(*) FROM users`

	var count int
	err := r.db.QueryRow(query).Scan(&count)
	if err != nil {
		r.logger.WithError(err).Error("Failed to count users")
		return 0, fmt.Errorf("failed to count users: %w", err)
	}

	r.logger.WithField("count", count).Debug("Users counted successfully")
	return count, nil
}

// GetStats returns user statistics
func (r *PostgresUserRepository) GetStats() (map[string]interface{}, error) {
	r.logger.Debug("Getting user statistics")

	stats := make(map[string]interface{})

	// Total users
	totalQuery := `SELECT COUNT(*) FROM users`
	var total int
	if err := r.db.QueryRow(totalQuery).Scan(&total); err != nil {
		r.logger.WithError(err).Error("Failed to get total user count")
		return nil, fmt.Errorf("failed to get total users: %w", err)
	}
	stats["total_users"] = total

	// Active users
	activeQuery := `SELECT COUNT(*) FROM users WHERE is_active = true`
	var active int
	if err := r.db.QueryRow(activeQuery).Scan(&active); err != nil {
		r.logger.WithError(err).Error("Failed to get active user count")
		return nil, fmt.Errorf("failed to get active users: %w", err)
	}
	stats["active_users"] = active

	// Inactive users
	stats["inactive_users"] = total - active

	// Users by role
	roleQuery := `SELECT role, COUNT(*) FROM users GROUP BY role`
	rows, err := r.db.Query(roleQuery)
	if err != nil {
		r.logger.WithError(err).Error("Failed to get users by role")
		return nil, fmt.Errorf("failed to get users by role: %w", err)
	}
	defer rows.Close()

	roleStats := make(map[string]int)
	for rows.Next() {
		var role string
		var count int
		if err := rows.Scan(&role, &count); err != nil {
			r.logger.WithError(err).Error("Failed to scan role stats")
			return nil, fmt.Errorf("failed to scan role stats: %w", err)
		}
		roleStats[role] = count
	}

	if err = rows.Err(); err != nil {
		r.logger.WithError(err).Error("Error iterating role stats rows")
		return nil, fmt.Errorf("error iterating role stats: %w", err)
	}

	stats["users_by_role"] = roleStats

	// Recent registrations (last 7 days)
	recentQuery := `SELECT COUNT(*) FROM users WHERE created_at >= NOW() - INTERVAL '7 days'`
	var recent int
	if err := r.db.QueryRow(recentQuery).Scan(&recent); err != nil {
		r.logger.WithError(err).Error("Failed to get recent registrations")
		return nil, fmt.Errorf("failed to get recent registrations: %w", err)
	}
	stats["recent_registrations"] = recent

	r.logger.Info("User statistics retrieved successfully")
	return stats, nil
}
