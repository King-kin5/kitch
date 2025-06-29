package main

import (
	"database/sql"
	"net/http"
	"time"

	database "kitch/Database"
	"kitch/configs"
	Auth "kitch/internal/Auth"
	"kitch/internal/security"
	utils "kitch/pkg/utils"

	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
)

func main() {
	_ = godotenv.Load()
	utils.Init("info")
	utils.Logger.Info("Starting Kitch streaming server...")

	e := echo.New()

	// Add debug middleware to log all requests
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			utils.Logger.Infof("Incoming request: %s %s", c.Request().Method, c.Request().URL.Path)
			return next(c)
		}
	})

	// Load configuration
	appConfig, err := configs.LoadConfig()
	if err != nil {
		utils.Logger.Fatalf("Failed to load configuration: %v", err)
	}

	// Validate configuration
	if err := appConfig.Validate(); err != nil {
		utils.Logger.Fatalf("Configuration validation failed: %v", err)
	}

	// Create security config from app config
	securityConfig := security.NewConfig(appConfig)

	// Initialize security middleware
	securityMiddlewareConfig := security.DefaultSecurityConfig()
	security.SetupSecurityMiddleware(e, securityConfig, securityMiddlewareConfig)

	// Add custom middleware
	e.Use(security.LoggingMiddleware)
	e.Use(security.AuditMiddleware)

	// Initialize database
	postgresDB, err := database.GetPostgresDB(appConfig)
	if err != nil {
		utils.Logger.Fatalf("Failed to initialize database: %v", err)
	}
	defer postgresDB.Close()

	// Initialize user store
	userStore := Auth.NewUserStore(postgresDB)

	// Initialize email service
	emailService, err := Auth.NewEmailService(appConfig)
	if err != nil {
		utils.Logger.Fatalf("Failed to initialize email service: %v", err)
	}

	// Initialize auth handler
	authHandler := Auth.NewHandler(userStore, securityConfig, emailService, postgresDB)

	// Setup authentication routes
	setupAuthRoutes(e, authHandler)

	// Setup protected routes
	setupProtectedRoutes(e, securityConfig, authHandler, postgresDB)

	// Print all registered routes for debugging
	for _, route := range e.Routes() {
		utils.Logger.Infof("Registered route: %s %s", route.Method, route.Path)
	}

	// Health check endpoint
	e.GET("/health", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"status":    "healthy",
			"timestamp": time.Now().UTC(),
			"version":   "1.0.0",
		})
	})

	utils.Logger.Info("Server listening on :8080")
	e.Logger.Fatal(e.Start(":8080"))
}

// setupAuthRoutes configures authentication routes
func setupAuthRoutes(e *echo.Echo, authHandler *Auth.Handler) {
	auth := e.Group("/api/v1/auth")
	auth.POST("/register", authHandler.RegisterUser)
	auth.POST("/login", authHandler.LoginUser)
	auth.POST("/refresh-token", authHandler.RefreshToken)
	auth.POST("/logout", authHandler.LogoutUser)
}

// setupProtectedRoutes configures routes that require authentication
func setupProtectedRoutes(e *echo.Echo, config *security.Config, authHandler *Auth.Handler, db *sql.DB) {
	// Create the protected group with authentication middleware
	protected := e.Group("/api/v1")
	protected.Use(security.AuthenticationMiddleware(config, db))

	// Create users group and log its creation
	users := protected.Group("/users")
	utils.Logger.Info("Setting up protected user routes under /api/v1/users")

	// Set up user routes with explicit path logging
	users.GET("/profile/:id", authHandler.Profile)
	utils.Logger.Info("Registered GET /api/v1/users/profile/:id endpoint")

	users.PUT("/update/:id", authHandler.UpdateUser)
	utils.Logger.Info("Registered PUT /api/v1/users/update/:id endpoint")
}
