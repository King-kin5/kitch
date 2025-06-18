package security

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func SetupSecurityMiddleware(e *echo.Echo, config *Config) {
	// CORS middleware
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: config.AllowedOrigins,
		AllowMethods: []string{http.MethodGet, http.MethodPut, http.MethodPost, http.MethodDelete},
		AllowHeaders: []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, echo.HeaderAuthorization},
	}))

	//Secure middleware

	e.Use(middleware.SecureWithConfig(middleware.SecureConfig{
		XSSProtection:         "1; mode=block",
		ContentTypeNosniff:    "nosniff",
		XFrameOptions:         "SAMEORIGIN",
		HSTSMaxAge:            31536000,
		HSTSExcludeSubdomains: false,
	}))

	// Rate limiting middleware
	e.Use(middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(20)))
}

func JWTMiddleware(Config *Config) echo.MiddlewareFunc {
	tokenManager := NewTokenManager(Config)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			authHeader := c.Request().Header.Get("Authorization")
			if authHeader == "" {
				return echo.NewHTTPError(http.StatusUnauthorized, "missing authorization Header")
			}

			tokenParts := strings.Split(authHeader, " ")
			if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
				return echo.NewHTTPError(http.StatusUnauthorized, "invalid authrorization header format")
			}

			claims, err := tokenManager.ValidateToken(tokenParts[1])
			if err != nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "invalid token")
			}

			c.Set("user_id", claims.UserID)
			return next(c)
		}
	}
}

// LoggingMiddleware logs request and response timing
func LoggingMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		start := time.Now()
		req := c.Request()
		res := c.Response()

		fmt.Printf("Request: %s %s\n", req.Method, req.URL.String())
		err := next(c)
		duration := time.Since(start)
		fmt.Printf("Response: %d in %v\n", res.Status, duration)
		return err
	}
}

// AuthenticationMiddleware checks JWT, skips excluded paths, sets user context
func AuthenticationMiddleware(config *Config) echo.MiddlewareFunc {
	tokenManager := NewTokenManager(config)

	// Production-ready excluded paths
	excludedPaths := []string{
		"/api/v1/auth/login",
		"/api/v1/auth/signup",
		"/api/v1/auth/me",
		"/api/v1/auth/forgot-password",
		"/api/v1/auth/reset-password",
		"/api/v1/auth/google-login",
		"/api/v1/auth/verify-email",
		"/api/v1/auth/refresh-token",
		"/health",
		"/docs",
		"/swagger",
		"/openapi.json",
		"/favicon.ico",
		"/robots.txt",
		"/static/",
		"/public/",
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			req := c.Request()

			// Skip OPTIONS
			if req.Method == http.MethodOptions {
				return next(c)
			}

			// Skip excluded paths
			path := req.URL.Path
			for _, p := range excludedPaths {
				if strings.HasPrefix(path, p) {
					return next(c)
				}
			}

			// Check Authorization header
			authHeader := req.Header.Get("Authorization")
			if authHeader == "" {
				return echo.NewHTTPError(http.StatusUnauthorized, "Authentication required")
			}

			token := strings.TrimPrefix(authHeader, "Bearer ")
			claims, err := tokenManager.ValidateToken(token)
			if err != nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "Invalid or expired token")
			}

			c.Set("user", claims)
			return next(c)
		}
	}
}

