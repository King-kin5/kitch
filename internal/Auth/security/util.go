package security

import (
	"fmt"
	"kitch/configs"
	"time"
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

	return &Config{
		JWTSecret:            appConfig.JWT.Secret,
		AccessTokenDuration:  accessDuration,
		RefreshTokenDuration: 7 * 24 * time.Hour, // 7 days
		AllowedOrigins:       []string{"http://localhost:3000", "https://yourdomain.com"},
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
