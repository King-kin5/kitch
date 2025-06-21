package configs

import (
	utils "kitch/pkg/utils"
	"os"
	"strconv"

	"github.com/badoux/checkmail"
)

type Config struct {
	Server struct {
		Port int
		Host string
	}
	Database struct {
		Host     string
		Port     int
		User     string
		Password string
		DBName   string
		SSLMode  string
	}
	Redis struct {
		Host     string
		Port     int
		Password string
		DB       int
	}
	RTMP struct {
		Port int
	}
	Stream struct {
		StoragePath     string
		SegmentDuration int
		MaxSegments     int
	}
	JWT struct {
		Secret     string
		Expiration string
	}
	FFmpeg struct {
		Path    string
		Threads int
	}
	Email struct {
		SMTPHost string
		SMTPPort int
		Username string
		Password string
		From     string
		Timeout  int // seconds
	}
	CORS struct {
		AllowedOrigins []string
		AllowedMethods []string
		AllowedHeaders []string
	}
}

func LoadConfig() (*Config, error) {
	config := &Config{}

	// Server config
	config.Server.Port = getEnvAsInt("SERVER_PORT", 8080)
	config.Server.Host = getEnv("SERVER_HOST", "0.0.0.0")

	// Database config
	config.Database.Host = getEnv("DB_HOST", "")
	config.Database.Port = getEnvAsInt("DB_PORT", 5432)
	config.Database.User = getEnv("DB_USER", "")
	config.Database.Password = getEnv("DB_PASSWORD", "")
	config.Database.DBName = getEnv("DB_NAME", "kitch")
	config.Database.SSLMode = getEnv("DB_SSLMODE", "disable")

	// Redis config
	config.Redis.Host = getEnv("REDIS_HOST", "")
	config.Redis.Port = getEnvAsInt("REDIS_PORT", 6379)
	config.Redis.Password = getEnv("REDIS_PASSWORD", "")
	config.Redis.DB = getEnvAsInt("REDIS_DB", 0)

	// RTMP config
	config.RTMP.Port = getEnvAsInt("RTMP_PORT", 1935)

	// Stream config
	config.Stream.StoragePath = getEnv("STREAM_STORAGE_PATH", "./storage")
	config.Stream.SegmentDuration = getEnvAsInt("STREAM_SEGMENT_DURATION", 6)
	config.Stream.MaxSegments = getEnvAsInt("STREAM_MAX_SEGMENTS", 10)

	// JWT config
	config.JWT.Secret = getEnv("JWT_SECRET", "")
	config.JWT.Expiration = getEnv("JWT_EXPIRATION", "24h")

	// FFmpeg config
	config.FFmpeg.Path = getEnv("FFMPEG_PATH", "/usr/bin/ffmpeg")
	config.FFmpeg.Threads = getEnvAsInt("FFMPEG_THREADS", 4)

	// Email config (values only from env, not shown/printed)
	config.Email.SMTPHost = getEnv("EMAIL_SMTP_HOST", "")
	config.Email.SMTPPort = getEnvAsInt("EMAIL_SMTP_PORT", 587)
	config.Email.Username = getEnv("EMAIL_USERNAME", "")
	config.Email.Password = getEnv("EMAIL_PASSWORD", "")
	config.Email.From = getEnv("EMAIL_FROM", "")
	config.Email.Timeout = getEnvAsInt("EMAIL_TIMEOUT", 10)

	// CORS config
	config.CORS.AllowedOrigins = getEnvAsSlice("CORS_ALLOWED_ORIGINS", []string{"http://localhost:3000", "https://yourdomain.com"})
	config.CORS.AllowedMethods = getEnvAsSlice("CORS_ALLOWED_METHODS", []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"})
	config.CORS.AllowedHeaders = getEnvAsSlice("CORS_ALLOWED_HEADERS", []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Requested-With"})

	return config, nil
}

// GetDatabaseURL returns the formatted database connection string
func (c *Config) GetDatabaseURL() string {
	return "user=" + c.Database.User +
		" password=" + c.Database.Password +
		" host=" + c.Database.Host +
		" port=" + strconv.Itoa(c.Database.Port) +
		" dbname=" + c.Database.DBName +
		" sslmode=" + c.Database.SSLMode
}

// GetRedisURL returns the formatted Redis connection string
func (c *Config) GetRedisURL() string {
	if c.Redis.Password != "" {
		return "redis://:" + c.Redis.Password + "@" + c.Redis.Host + ":" + strconv.Itoa(c.Redis.Port) + "/" + strconv.Itoa(c.Redis.DB)
	}
	return "redis://" + c.Redis.Host + ":" + strconv.Itoa(c.Redis.Port) + "/" + strconv.Itoa(c.Redis.DB)
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	if value, exists := os.LookupEnv(key); exists {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvAsSlice(key string, defaultValue []string) []string {
	if value, exists := os.LookupEnv(key); exists {
		return utils.SplitString(value)
	}
	return defaultValue
}

func (c *Config) Validate() error {
	var errors []string

	// JWT validation
	if c.JWT.Secret == "" {
		errors = append(errors, "JWT_SECRET is required")
	} else if len(c.JWT.Secret) < 32 {
		errors = append(errors, "JWT_SECRET must be at least 32 characters long")
	}

	// Database validation
	if c.Database.Host == "" {
		errors = append(errors, "DB_HOST is required")
	}
	if c.Database.User == "" {
		errors = append(errors, "DB_USER is required")
	}
	if c.Database.Password == "" {
		errors = append(errors, "DB_PASSWORD is required")
	}
	if c.Database.DBName == "" {
		errors = append(errors, "DB_NAME is required")
	}
	if c.Database.Port <= 0 || c.Database.Port > 65535 {
		errors = append(errors, "DB_PORT must be between 1 and 65535")
	}

	// Email validation
	if c.Email.SMTPHost == "" {
		errors = append(errors, "EMAIL_SMTP_HOST is required")
	}
	if c.Email.Username == "" {
		errors = append(errors, "EMAIL_USERNAME is required")
	}
	if c.Email.Password == "" {
		errors = append(errors, "EMAIL_PASSWORD is required")
	}
	if c.Email.From == "" {
		errors = append(errors, "EMAIL_FROM is required")
	}
	if c.Email.SMTPPort <= 0 || c.Email.SMTPPort > 65535 {
		errors = append(errors, "EMAIL_SMTP_PORT must be between 1 and 65535")
	}
	if c.Email.Timeout <= 0 || c.Email.Timeout > 300 {
		errors = append(errors, "EMAIL_TIMEOUT must be between 1 and 300 seconds")
	}

	// Server validation
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		errors = append(errors, "SERVER_PORT must be between 1 and 65535")
	}
	if c.Server.Host == "" {
		errors = append(errors, "SERVER_HOST is required")
	}

	// Redis validation (optional but recommended for production)
	if c.Redis.Host == "" {
		utils.Logger.Warn("REDIS_HOST not set - some features may be limited")
	} else {
		if c.Redis.Port <= 0 || c.Redis.Port > 65535 {
			errors = append(errors, "REDIS_PORT must be between 1 and 65535")
		}
		if c.Redis.DB < 0 || c.Redis.DB > 15 {
			errors = append(errors, "REDIS_DB must be between 0 and 15")
		}
	}

	// RTMP validation
	if c.RTMP.Port <= 0 || c.RTMP.Port > 65535 {
		errors = append(errors, "RTMP_PORT must be between 1 and 65535")
	}

	// Stream validation
	if c.Stream.StoragePath == "" {
		errors = append(errors, "STREAM_STORAGE_PATH is required")
	}
	if c.Stream.SegmentDuration <= 0 || c.Stream.SegmentDuration > 60 {
		errors = append(errors, "STREAM_SEGMENT_DURATION must be between 1 and 60 seconds")
	}
	if c.Stream.MaxSegments <= 0 || c.Stream.MaxSegments > 1000 {
		errors = append(errors, "STREAM_MAX_SEGMENTS must be between 1 and 1000")
	}

	// FFmpeg validation
	if c.FFmpeg.Path == "" {
		errors = append(errors, "FFMPEG_PATH is required")
	}
	if c.FFmpeg.Threads <= 0 || c.FFmpeg.Threads > 32 {
		errors = append(errors, "FFMPEG_THREADS must be between 1 and 32")
	}

	// Security validations
	if len(errors) == 0 {
		// Additional security checks
		if c.JWT.Expiration == "" {
			errors = append(errors, "JWT_EXPIRATION is required")
		}

		// Validate email format
		if !isValidEmail(c.Email.From) {
			errors = append(errors, "EMAIL_FROM must be a valid email address")
		}

		// Check for weak passwords in config (basic check)
		if len(c.Database.Password) < 8 {
			utils.Logger.Warn("Database password is shorter than 8 characters - consider using a stronger password")
		}
		if len(c.Email.Password) < 8 {
			utils.Logger.Warn("Email password is shorter than 8 characters - consider using a stronger password")
		}
	}

	// Log all errors
	if len(errors) > 0 {
		for _, err := range errors {
			utils.Logger.Errorf("Configuration error: %s", err)
		}
		return utils.ErrInternalServer
	}

	utils.Logger.Info("Configuration validation passed")
	return nil
}

// isValidEmail performs proper email validation using checkmail library
func isValidEmail(email string) bool {
	if len(email) == 0 || len(email) > 254 {
		return false
	}

	// Use proper email validation library
	err := checkmail.ValidateFormat(email)
	return err == nil
}

// ValidateProductionConfig performs additional production-specific validations
func (c *Config) ValidateProductionConfig() error {
	var warnings []string

	// Production security warnings
	if c.Server.Host == "0.0.0.0" {
		warnings = append(warnings, "SERVER_HOST is set to 0.0.0.0 - ensure proper firewall rules")
	}

	if c.Database.SSLMode == "disable" {
		warnings = append(warnings, "Database SSL is disabled - not recommended for production")
	}

	if c.JWT.Expiration == "24h" {
		warnings = append(warnings, "JWT_EXPIRATION is set to 24h - consider shorter duration for better security")
	}

	if c.Redis.Host == "" {
		warnings = append(warnings, "Redis not configured - session management and caching will be limited")
	}

	// Log warnings
	for _, warning := range warnings {
		utils.Logger.Warnf("Production warning: %s", warning)
	}

	return nil
}
