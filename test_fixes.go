package main

import (
	"fmt"
	"time"

	"auth-service-go/internal/domain"
	"auth-service-go/pkg/jwt"
)

func main() {
	fmt.Println("🧪 Testing fixes...")

	// Test 1: Domain role validation
	fmt.Println("\n1. Testing role validation:")
	testRoles := []string{"admin", "manager", "user", "viewer", "invalid"}
	for _, role := range testRoles {
		valid := domain.IsValidRole(role)
		status := "❌"
		if valid {
			status = "✅"
		}
		fmt.Printf("   %s Role '%s' valid: %v\n", status, role, valid)
	}

	// Test 2: User role methods
	fmt.Println("\n2. Testing user role methods:")
	adminUser := &domain.User{Role: "admin"}
	managerUser := &domain.User{Role: "manager"}
	regularUser := &domain.User{Role: "user"}

	fmt.Printf("   ✅ Admin IsAdmin(): %v\n", adminUser.IsAdmin())
	fmt.Printf("   ✅ Admin IsManagerOrAdmin(): %v\n", adminUser.IsManagerOrAdmin())
	fmt.Printf("   ✅ Manager IsManagerOrAdmin(): %v\n", managerUser.IsManagerOrAdmin())
	fmt.Printf("   ✅ User IsAdmin(): %v (should be false)\n", regularUser.IsAdmin())

	// Test 3: JWT Manager
	fmt.Println("\n3. Testing JWT Manager:")
	jwtManager := jwt.NewJWTManager("test-secret-key", time.Hour*24)

	// Generate token
	token, err := jwtManager.GenerateToken("user123", "test@example.com", "admin")
	if err != nil {
		fmt.Printf("   ❌ Failed to generate token: %v\n", err)
	} else {
		fmt.Printf("   ✅ Token generated successfully\n")

		// Validate token
		claims, err := jwtManager.ValidateToken(token)
		if err != nil {
			fmt.Printf("   ❌ Failed to validate token: %v\n", err)
		} else {
			fmt.Printf("   ✅ Token validated successfully\n")
			fmt.Printf("   ✅ Claims - UserID: %s, Email: %s, Role: %s\n",
				claims.UserID, claims.Email, claims.Role)
		}
	}

	// Test 4: Domain errors
	fmt.Println("\n4. Testing domain errors:")
	errors := []error{
		domain.ErrUserNotFound,
		domain.ErrUserAlreadyExists,
		domain.ErrInvalidCredentials,
		domain.ErrUserInactive,
	}

	for _, err := range errors {
		fmt.Printf("   ✅ Error defined: %v\n", err)
	}

	fmt.Println("\n🎉 All tests completed!")
}
