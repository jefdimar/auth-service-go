package jwt

import (
	"fmt"
	"time"

	"auth-service-go/internal/domain"
	"auth-service-go/pkg/logger"

	"github.com/golang-jwt/jwt/v5"
)

// JWTManager handles JWT token operations
type JWTManager struct {
	secretKey     string
	tokenDuration time.Duration
	logger        logger.Logger
}

// Claims represents JWT claims
type Claims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

// NewJWTManager creates a new JWT manager
func NewJWTManager(secretKey string, tokenDuration time.Duration) *JWTManager {
	return &JWTManager{
		secretKey:     secretKey,
		tokenDuration: tokenDuration,
		logger:        logger.GetLogger().WithField("component", "jwt_manager"),
	}
}

// GenerateToken generates a new JWT token for a user
func (manager *JWTManager) GenerateToken(user *domain.User) (string, time.Time, error) {
	manager.logger.WithFields(map[string]interface{}{
		"user_id": user.ID,
		"email":   user.Email,
		"role":    user.Role,
	}).Debug("Generating JWT token")

	expiresAt := time.Now().Add(manager.tokenDuration)

	claims := Claims{
		UserID: user.ID,
		Email:  user.Email,
		Role:   user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "auth-service",
			Subject:   user.ID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(manager.secretKey))
	if err != nil {
		manager.logger.WithError(err).Error("Failed to sign JWT token")
		return "", time.Time{}, fmt.Errorf("failed to sign token: %w", err)
	}

	manager.logger.WithFields(map[string]interface{}{
		"user_id":    user.ID,
		"expires_at": expiresAt,
	}).Info("JWT token generated successfully")

	return tokenString, expiresAt, nil
}

// ValidateToken validates a JWT token and returns the claims
func (manager *JWTManager) ValidateToken(tokenString string) (*Claims, error) {
	manager.logger.Debug("Validating JWT token")

	token, err := jwt.ParseWithClaims(
		tokenString,
		&Claims{},
		func(token *jwt.Token) (interface{}, error) {
			// Validate signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(manager.secretKey), nil
		},
	)

	if err != nil {
		manager.logger.WithError(err).Warn("Failed to parse JWT token")
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		manager.logger.Error("Invalid token claims")
		return nil, fmt.Errorf("invalid token claims")
	}

	if !token.Valid {
		manager.logger.Warn("Invalid JWT token")
		return nil, fmt.Errorf("invalid token")
	}

	// Check if token is expired
	if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(time.Now()) {
		manager.logger.Warn("JWT token expired")
		return nil, domain.ErrTokenExpired
	}

	manager.logger.WithFields(map[string]interface{}{
		"user_id": claims.UserID,
		"email":   claims.Email,
		"role":    claims.Role,
	}).Debug("JWT token validated successfully")

	return claims, nil
}

// RefreshToken generates a new token if the current one is valid but close to expiry
func (manager *JWTManager) RefreshToken(tokenString string) (string, time.Time, error) {
	claims, err := manager.ValidateToken(tokenString)
	if err != nil {
		return "", time.Time{}, err
	}

	// Check if token is close to expiry (within 1 hour)
	if claims.ExpiresAt != nil && time.Until(claims.ExpiresAt.Time) > time.Hour {
		return "", time.Time{}, fmt.Errorf("token doesn't need refresh yet")
	}

	// Create new token with same claims but new expiry
	expiresAt := time.Now().Add(manager.tokenDuration)
	newClaims := Claims{
		UserID: claims.UserID,
		Email:  claims.Email,
		Role:   claims.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "auth-service",
			Subject:   claims.UserID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, newClaims)
	tokenString, err = token.SignedString([]byte(manager.secretKey))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign refreshed token: %w", err)
	}

	manager.logger.WithField("user_id", claims.UserID).Info("JWT token refreshed successfully")
	return tokenString, expiresAt, nil
}
