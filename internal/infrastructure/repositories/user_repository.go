package repositories

import (
	"database/sql"
	"time"

	"auth-service-go/internal/domain"
	"auth-service-go/pkg/logger"

	"github.com/google/uuid"
)

type postgresUserRepository struct {
	db     *sql.DB
	logger logger.Logger
}

// NewPostgresUserRepository creates a new PostgreSQL user repository
func NewPostgresUserRepository(db *sql.DB) domain.UserRepository {
	return &postgresUserRepository{
		db:     db,
		logger: logger.GetLogger().WithField("component", "user_repository"),
	}
}

// Create creates a new user
func (r *postgresUserRepository) Create(user *domain.User) error {
	r.logger.WithField("email", user.Email).Info("Creating new user")

	// Generate UUID if not provided
	if user.ID == "" {
		user.ID = uuid.New().String()
	}

	// Set timestamps
	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now

	// Set default role if not provided
	if user.Role == "" {
		user.Role = string(domain.RoleUser)
	}

	// Hash password before storing
	if err := user.HashPassword(); err != nil {
		r.logger.WithError(err).Error("Failed to hash password")
		return err
	}

	query := `
		INSERT INTO users (id, email, password, first_name, last_name, role, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	_, err := r.db.Exec(query,
		user.ID, user.Email, user.Password, user.FirstName, user.LastName,
		user.Role, user.IsActive, user.CreatedAt, user.UpdatedAt,
	)

	if err != nil {
		r.logger.WithError(err).Error("Failed to create user")
		return err
	}

	r.logger.WithFields(map[string]interface{}{
		"user_id": user.ID,
		"email":   user.Email,
	}).Info("User created successfully")

	return nil
}

// GetByID retrieves a user by ID
func (r *postgresUserRepository) GetByID(id string) (*domain.User, error) {
	r.logger.WithField("user_id", id).Debug("Getting user by ID")

	user := &domain.User{}
	query := `
		SELECT id, email, password, first_name, last_name, role, is_active, created_at, updated_at
		FROM users WHERE id = $1`

	err := r.db.QueryRow(query, id).Scan(
		&user.ID, &user.Email, &user.Password, &user.FirstName, &user.LastName,
		&user.Role, &user.IsActive, &user.CreatedAt, &user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrUserNotFound
		}
		r.logger.WithError(err).Error("Failed to get user by ID")
		return nil, err
	}

	return user, nil
}

// GetByEmail retrieves a user by email
func (r *postgresUserRepository) GetByEmail(email string) (*domain.User, error) {
	r.logger.WithField("email", email).Debug("Getting user by email")

	user := &domain.User{}
	query := `
		SELECT id, email, password, first_name, last_name, role, is_active, created_at, updated_at
		FROM users WHERE email = $1`

	err := r.db.QueryRow(query, email).Scan(
		&user.ID, &user.Email, &user.Password, &user.FirstName, &user.LastName,
		&user.Role, &user.IsActive, &user.CreatedAt, &user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrUserNotFound
		}
		r.logger.WithError(err).Error("Failed to get user by email")
		return nil, err
	}

	return user, nil
}

// Update updates a user
func (r *postgresUserRepository) Update(user *domain.User) error {
	r.logger.WithField("user_id", user.ID).Info("Updating user")

	user.UpdatedAt = time.Now()

	query := `
		UPDATE users 
		SET email = $2, first_name = $3, last_name = $4, role = $5, is_active = $6, updated_at = $7
		WHERE id = $1`

	result, err := r.db.Exec(query,
		user.ID, user.Email, user.FirstName, user.LastName,
		user.Role, user.IsActive, user.UpdatedAt,
	)

	if err != nil {
		r.logger.WithError(err).Error("Failed to update user")
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return domain.ErrUserNotFound
	}

	r.logger.WithField("user_id", user.ID).Info("User updated successfully")
	return nil
}

// Delete deletes a user
func (r *postgresUserRepository) Delete(id string) error {
	r.logger.WithField("user_id", id).Info("Deleting user")

	query := `DELETE FROM users WHERE id = $1`
	result, err := r.db.Exec(query, id)

	if err != nil {
		r.logger.WithError(err).Error("Failed to delete user")
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return domain.ErrUserNotFound
	}

	r.logger.WithField("user_id", id).Info("User deleted successfully")
	return nil
}

// List retrieves users with pagination
func (r *postgresUserRepository) List(limit, offset int) ([]*domain.User, error) {
	r.logger.WithFields(map[string]interface{}{
		"limit":  limit,
		"offset": offset,
	}).Debug("Listing users")

	query := `
		SELECT id, email, password, first_name, last_name, role, is_active, created_at, updated_at
		FROM users 
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2`

	rows, err := r.db.Query(query, limit, offset)
	if err != nil {
		r.logger.WithError(err).Error("Failed to list users")
		return nil, err
	}
	defer rows.Close()

	var users []*domain.User
	for rows.Next() {
		user := &domain.User{}
		err := rows.Scan(
			&user.ID, &user.Email, &user.Password, &user.FirstName, &user.LastName,
			&user.Role, &user.IsActive, &user.CreatedAt, &user.UpdatedAt,
		)
		if err != nil {
			r.logger.WithError(err).Error("Failed to scan user row")
			return nil, err
		}
		users = append(users, user)
	}

	return users, nil
}

// ExistsByEmail checks if a user exists by email
func (r *postgresUserRepository) ExistsByEmail(email string) (bool, error) {
	r.logger.WithField("email", email).Debug("Checking if user exists by email")

	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)`
	err := r.db.QueryRow(query, email).Scan(&exists)

	if err != nil {
		r.logger.WithError(err).Error("Failed to check user existence")
		return false, err
	}

	return exists, nil
}
