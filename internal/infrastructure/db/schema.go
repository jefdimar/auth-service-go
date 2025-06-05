package db

import (
	"auth-service-go/pkg/logger"
	"database/sql"
)

// CreateSchema creates the database schema
func CreateSchema(db *sql.DB) error {
	log := logger.GetLogger()
	log.Info("Creating database schema...")

	// Users table
	usersTable := `
	CREATE TABLE IF NOT EXISTS users (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		email VARCHAR(255) UNIQUE NOT NULL,
		password VARCHAR(255) NOT NULL,
		first_name VARCHAR(100) NOT NULL,
		last_name VARCHAR(100) NOT NULL,
		role VARCHAR(50) NOT NULL DEFAULT 'user',
		is_active BOOLEAN NOT NULL DEFAULT true,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
	);`

	if _, err := db.Exec(usersTable); err != nil {
		return err
	}

	// Create indexes
	indexes := []string{
		`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);`,
		`CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);`,
		`CREATE INDEX IF NOT EXISTS idx_users_is_active ON users(is_active);`,
		`CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);`,
	}

	for _, index := range indexes {
		if _, err := db.Exec(index); err != nil {
			log.WithError(err).Warn("Failed to create index")
		}
	}

	// Create updated_at trigger function
	triggerFunction := `
	CREATE OR REPLACE FUNCTION update_updated_at_column()
	RETURNS TRIGGER AS $$
	BEGIN
		NEW.updated_at = CURRENT_TIMESTAMP;
		RETURN NEW;
	END;
	$$ language 'plpgsql';`

	if _, err := db.Exec(triggerFunction); err != nil {
		log.WithError(err).Warn("Failed to create trigger function")
	}

	// Create trigger for users table
	trigger := `
	DROP TRIGGER IF EXISTS update_users_updated_at ON users;
	CREATE TRIGGER update_users_updated_at
		BEFORE UPDATE ON users
		FOR EACH ROW
		EXECUTE FUNCTION update_updated_at_column();`

	if _, err := db.Exec(trigger); err != nil {
		log.WithError(err).Warn("Failed to create trigger")
	}

	log.Info("Database schema created successfully")
	return nil
}
