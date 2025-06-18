package configs

import (
	"os"
	"strconv"
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
}

func LoadConfig() (*Config, error) {
	config := &Config{}

	// Server config
	config.Server.Port = getEnvAsInt("SERVER_PORT", 8080)
	config.Server.Host = getEnv("SERVER_HOST", "0.0.0.0")

	// Database config
	config.Database.Host = getEnv("DB_HOST", "localhost")
	config.Database.Port = getEnvAsInt("DB_PORT", 5432)
	config.Database.User = getEnv("DB_USER", "postgres")
	config.Database.Password = getEnv("DB_PASSWORD", "")
	config.Database.DBName = getEnv("DB_NAME", "kitch")
	config.Database.SSLMode = getEnv("DB_SSLMODE", "disable")

	// Redis config
	config.Redis.Host = getEnv("REDIS_HOST", "localhost")
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
