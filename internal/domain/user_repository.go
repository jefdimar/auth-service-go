package domain

// UserRepository defines the interface for user data operations
type UserRepository interface {
	// Basic CRUD operations
	Create(user *User) error
	GetByID(id string) (*User, error)
	GetByEmail(email string) (*User, error)
	Update(user *User) error
	Delete(id string) error

	// Query operations
	ExistsByEmail(email string) (bool, error)
	List(offset, limit int) ([]*User, error)
	Count() (int, error)

	// Statistics
	GetStats() (map[string]interface{}, error)
}
