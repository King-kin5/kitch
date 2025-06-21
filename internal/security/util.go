package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"kitch/configs"

	"strings"
	"time"

	"github.com/google/uuid"
)

// Config holds all security related configurations
type Config struct {
	JWTSecret            string
	AccessTokenDuration  time.Duration
	RefreshTokenDuration time.Duration
	AllowedOrigins       []string
}

// NewConfig creates a new security configuration
func NewConfig(appConfig *configs.Config) *Config {
	// Parse JWT expiration from config
	accessDuration, _ := time.ParseDuration(appConfig.JWT.Expiration)
	if accessDuration == 0 {
		accessDuration = 15 * time.Minute // Default fallback
	}

	// Use CORS configuration from app config, with fallback defaults
	allowedOrigins := appConfig.CORS.AllowedOrigins
	if len(allowedOrigins) == 0 {
		allowedOrigins = []string{"http://localhost:3000", "https://yourdomain.com"}
	}

	return &Config{
		JWTSecret:            appConfig.JWT.Secret,
		AccessTokenDuration:  accessDuration,
		RefreshTokenDuration: 7 * 24 * time.Hour, // 7 days
		AllowedOrigins:       allowedOrigins,
	}
}

// ValidateJWTSecret checks if the JWT secret is properly configured
func ValidateJWTSecret(secret string) error {
	if secret == "" {
		return fmt.Errorf("JWT_SECRET environment variable is required")
	}
	if len(secret) < 32 {
		return fmt.Errorf("JWT_SECRET must be at least 32 characters long")
	}
	return nil
}

// GenerateRandomCode generates a cryptographically secure random code
func GenerateRandomCode(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("code length must be positive")
	}

	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Convert to hex and take first 'length' characters
	hexStr := hex.EncodeToString(bytes)
	if len(hexStr) < length {
		return "", fmt.Errorf("generated code too short")
	}

	return hexStr[:length], nil
}

// SecurityUtils provides common security utility functions
type SecurityUtils struct{}

// NewSecurityUtils creates a new security utils instance
func NewSecurityUtils() *SecurityUtils {
	return &SecurityUtils{}
}

// ValidateEmailFormat validates email format
func (su *SecurityUtils) ValidateEmailFormat(email string) bool {
	// Basic email validation - consider using a proper email validation library
	if len(email) < 3 || len(email) > 254 {
		return false
	}

	atIndex := -1
	dotIndex := -1

	for i, char := range email {
		if char == '@' {
			if atIndex != -1 {
				return false // Multiple @ symbols
			}
			atIndex = i
		} else if char == '.' {
			dotIndex = i
		}
	}

	return atIndex > 0 && dotIndex > atIndex+1 && dotIndex < len(email)-1
}

// SanitizeInput removes potentially dangerous characters
func (su *SecurityUtils) SanitizeInput(input string) string {
	// Basic input sanitization - consider using a proper HTML sanitizer
	// This is a simple example and should be enhanced based on your needs
	dangerousChars := []string{"<script>", "</script>", "javascript:", "onload=", "onerror="}
	result := input

	for _, char := range dangerousChars {
		// Replace with empty string or HTML entities
		result = strings.ReplaceAll(result, char, "")
	}

	return result
}

// HashString creates a hash of a string (for non-password data)
func (su *SecurityUtils) HashString(data string) (string, error) {
	// Use a fast hash for non-sensitive data
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:]), nil
}

// IsValidUUID checks if a string is a valid UUID
func (su *SecurityUtils) IsValidUUID(u string) bool {
	_, err := uuid.Parse(u)
	return err == nil
}
