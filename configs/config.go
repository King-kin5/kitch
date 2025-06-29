package configs

import (
	utils "kitch/pkg/utils"
	"os"
	"strconv"

	"github.com/joho/godotenv"
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
	
	// Try to load .env file with better error handling
	if err := godotenv.Load(); err != nil {
		if err := godotenv.Load(".env"); err != nil {
			if err := godotenv.Load("../.env"); err != nil {
				utils.Logger.Warn("No .env file found, using system environment variables only")
			}
		}
	}

	// Server config
	if v := os.Getenv("SERVER_PORT"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			config.Server.Port = i
		} else {
			config.Server.Port = 8080
		}
	} else {
		config.Server.Port = 8080
	}
	if v := os.Getenv("SERVER_HOST"); v != "" {
		config.Server.Host = v
	} else {
		config.Server.Host = "0.0.0.0"
	}

	// Database config
	config.Database.Host = os.Getenv("DB_HOST")
	if v := os.Getenv("DB_PORT"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			config.Database.Port = i
		} else {
			config.Database.Port = 5432
		}
	} else {
		config.Database.Port = 5432
	}
	config.Database.User = os.Getenv("DB_USER")
	config.Database.Password = os.Getenv("DB_PASSWORD")
	config.Database.DBName = os.Getenv("DB_NAME")
	if config.Database.DBName == "" {
		config.Database.DBName = "kitch"
	}
	config.Database.SSLMode = os.Getenv("DB_SSLMODE")
	if config.Database.SSLMode == "" {
		config.Database.SSLMode = "disable"
	}

	// Redis config
	config.Redis.Host = os.Getenv("REDIS_HOST")
	if v := os.Getenv("REDIS_PORT"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			config.Redis.Port = i
		} else {
			config.Redis.Port = 6379
		}
	} else {
		config.Redis.Port = 6379
	}
	config.Redis.Password = os.Getenv("REDIS_PASSWORD")
	if v := os.Getenv("REDIS_DB"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			config.Redis.DB = i
		} else {
			config.Redis.DB = 0
		}
	} else {
		config.Redis.DB = 0
	}

	// RTMP config
	if v := os.Getenv("RTMP_PORT"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			config.RTMP.Port = i
		} else {
			config.RTMP.Port = 1935
		}
	} else {
		config.RTMP.Port = 1935
	}

	// Stream config
	config.Stream.StoragePath = os.Getenv("STREAM_STORAGE_PATH")
	if config.Stream.StoragePath == "" {
		config.Stream.StoragePath = "./storage"
	}
	if v := os.Getenv("STREAM_SEGMENT_DURATION"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			config.Stream.SegmentDuration = i
		} else {
			config.Stream.SegmentDuration = 6
		}
	} else {
		config.Stream.SegmentDuration = 6
	}
	if v := os.Getenv("STREAM_MAX_SEGMENTS"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			config.Stream.MaxSegments = i
		} else {
			config.Stream.MaxSegments = 10
		}
	} else {
		config.Stream.MaxSegments = 10
	}

	// JWT config
	config.JWT.Secret = os.Getenv("JWT_SECRET")
	config.JWT.Expiration = os.Getenv("JWT_EXPIRATION")
	if config.JWT.Expiration == "" {
		config.JWT.Expiration = "24h"
	}

	// FFmpeg config
	config.FFmpeg.Path = os.Getenv("FFMPEG_PATH")
	if config.FFmpeg.Path == "" {
		config.FFmpeg.Path = "/usr/bin/ffmpeg"
	}
	if v := os.Getenv("FFMPEG_THREADS"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			config.FFmpeg.Threads = i
		} else {
			config.FFmpeg.Threads = 4
		}
	} else {
		config.FFmpeg.Threads = 4
	}

	// Email config
	config.Email.SMTPHost = os.Getenv("EMAIL_SMTP_HOST")
	if v := os.Getenv("EMAIL_SMTP_PORT"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			config.Email.SMTPPort = i
		} else {
			config.Email.SMTPPort = 587
		}
	} else {
		config.Email.SMTPPort = 587
	}
	config.Email.Username = os.Getenv("EMAIL_USERNAME")
	config.Email.Password = os.Getenv("EMAIL_PASSWORD")
	if v := os.Getenv("EMAIL_TIMEOUT"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			config.Email.Timeout = i
		} else {
			config.Email.Timeout = 10
		}
	} else {
		config.Email.Timeout = 10
	}

	// CORS config
	if v := os.Getenv("CORS_ALLOWED_ORIGINS"); v != "" {
		config.CORS.AllowedOrigins = utils.SplitString(v)
	} else {
		config.CORS.AllowedOrigins = []string{"http://localhost:8080", "https://yourdomain.com"}
	}
	if v := os.Getenv("CORS_ALLOWED_METHODS"); v != "" {
		config.CORS.AllowedMethods = utils.SplitString(v)
	} else {
		config.CORS.AllowedMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	}
	if v := os.Getenv("CORS_ALLOWED_HEADERS"); v != "" {
		config.CORS.AllowedHeaders = utils.SplitString(v)
	} else {
		config.CORS.AllowedHeaders = []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Requested-With"}
	}

	// Debug: Print loaded config values (remove in production)
	utils.Logger.Infof("Loaded config - DB_HOST: %s, JWT_SECRET: %s", config.Database.Host, maskSecret(config.JWT.Secret))

	return config, nil
}

// Helper function to mask secrets for logging
func maskSecret(secret string) string {
	if len(secret) == 0 {
		return "<EMPTY>"
	}
	if len(secret) <= 8 {
		return "<MASKED>"
	}
	return secret[:4] + "..." + secret[len(secret)-4:]
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