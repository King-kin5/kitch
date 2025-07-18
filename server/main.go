package main

import (
	"context"
	"database/sql"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	database "kitch/Database"
	"kitch/configs"
	Auth "kitch/internal/Auth"
	"kitch/internal/rtmp"
	"kitch/internal/security"
	"kitch/internal/stream"
	utils "kitch/pkg/utils"

	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
)

func main() {
	_ = godotenv.Load()
	utils.Init("info")
	utils.Logger.Info("Starting Kitch streaming server...")
	e := echo.New()
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			utils.Logger.Infof("Incoming request: %s %s", c.Request().Method, c.Request().URL.Path)
			return next(c)
		}
	})
	appConfig, err := configs.LoadConfig()
	if err != nil {
		utils.Logger.Fatalf("Failed to load configuration: %v", err)
	}

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

	// Initialize stream store and handler
	streamStore := stream.NewStreamStore(postgresDB)
	streamHandler := stream.NewHandler(streamStore)

	// Setup authentication routes
	setupAuthRoutes(e, authHandler)

	// Setup protected routes
	setupProtectedRoutes(e, securityConfig, authHandler, postgresDB)

	// Setup stream routes
	setupStreamRoutes(e, securityConfig, streamHandler, postgresDB)

	// Initialize RTMP datastore and validator
	rtmpDatastore := &rtmp.RTMPDatastore{
		StreamStore: streamStore,
	}
	streamValidator := &rtmp.DatabaseStreamValidator{
		Datastore: rtmpDatastore,
	}
	// Initialize RTMP server
	rtmpServer := rtmp.NewServer(appConfig.RTMP.Port, streamValidator)

	// Start RTMP server
	if err := rtmpServer.Start(); err != nil {
		utils.Logger.Fatalf("Failed to start RTMP server: %v", err)
	}
	defer rtmpServer.Stop()

	// Initialize RTMP handler
	rtmpHandler := rtmp.NewHandler(rtmpServer)

	// Setup RTMP server routes
	setupRTMPRoutes(e, rtmpHandler)

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

	// Setup graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Start HTTP server in a goroutine
	go func() {
		utils.Logger.Info("HTTP server listening on :8080")
		if err := e.Start(":8080"); err != nil && err != http.ErrServerClosed {
			utils.Logger.Errorf("HTTP server error: %v", err)
		}
	}()
	// Wait for shutdown signal
	<-ctx.Done()
	utils.Logger.Info("Shutdown signal received, starting graceful shutdown...")
	// Create shutdown context with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// Shutdown HTTP server
	if err := e.Shutdown(shutdownCtx); err != nil {
		utils.Logger.Errorf("HTTP server shutdown error: %v", err)
	}
	utils.Logger.Info("Server shutdown complete")
}

//	//
//	//
//	//
//	//
//
// setupAuthRoutes configures authentication routes
//
//	//
//	//
//	//
//	//
func setupAuthRoutes(e *echo.Echo, authHandler *Auth.Handler) {
	auth := e.Group("/api/v1/auth")
	auth.POST("/register", authHandler.RegisterUser)
	auth.POST("/login", authHandler.LoginUser)
	auth.POST("/refresh-token", authHandler.RefreshToken)
	auth.POST("/logout", authHandler.LogoutUser)
}

//                                                                         //
//                                                                         //
//                                                                         //
//                                                                         //
//                                                                         //
// setupProtectedRoutes configures routes that require authentication//
//                                                                         //
//                                                                         //
//                                                                         //
//                                                                         //

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

	//                             //
	//                             //
	//Stream key management routes
	//                             //
	//                             //
	users.POST("/stream-keys", authHandler.GenerateStreamKey)
	utils.Logger.Info("Registered POST /api/v1/users/stream-keys endpoint")

	users.GET("/stream-keys", authHandler.GetUserStreamKeys)
	utils.Logger.Info("Registered GET /api/v1/users/stream-keys endpoint")

	users.GET("/stream-keys/:id", authHandler.GetStreamKey)
	utils.Logger.Info("Registered GET /api/v1/users/stream-keys/:id endpoint")

	users.PUT("/stream-keys/:id/deactivate", authHandler.DeactivateStreamKey)
	utils.Logger.Info("Registered PUT /api/v1/users/stream-keys/:id/deactivate endpoint")

	users.DELETE("/stream-keys/:id", authHandler.DeleteStreamKey)
	utils.Logger.Info("Registered DELETE /api/v1/users/stream-keys/:id endpoint")
}

//	//
//	//
//	//
//	//
//	//
//
// setupRTMPRoutes configures RTMP-related API routes//
//
//	//
//	//
//	//
//	//
//	//
//	//
func setupRTMPRoutes(e *echo.Echo, rtmpHandler *rtmp.Handler) {
	rtmp := e.Group("/api/v1/rtmp")

	// RTMP server status endpoint
	rtmp.GET("/status", rtmpHandler.GetStatus)

	// RTMP streams endpoints
	rtmp.GET("/streams", rtmpHandler.GetStreams)
	rtmp.GET("/streams/:id", rtmpHandler.GetStream)

	// RTMP connections endpoint
	rtmp.GET("/connections", rtmpHandler.GetConnections)

	// RTMP configuration endpoint
	rtmp.PUT("/config", rtmpHandler.UpdateConfig)

	utils.Logger.Info("Setting up RTMP API routes under /api/v1/rtmp")
}

//	//
//	//
//	//
//	//
//	//
//	//
//
// setupStreamRoutes configures stream-related API routes//
//
//	//
//	//
//	//
//	//
//	//
func setupStreamRoutes(e *echo.Echo, config *security.Config, streamHandler *stream.Handler, db *sql.DB) {
	// Create the protected group with authentication middleware
	protected := e.Group("/api/v1/streams")
	protected.Use(security.AuthenticationMiddleware(config, db))

	// Stream key management routes
	protected.POST("/keys", streamHandler.GenerateStreamKey)
	protected.GET("/keys", streamHandler.GetStreamKeys)
	protected.GET("/keys/:id", streamHandler.GetStreamKey)
	protected.PUT("/keys/:id/deactivate", streamHandler.DeactivateStreamKey)
	protected.DELETE("/keys/:id", streamHandler.DeleteStreamKey)

	// Stream management routes
	protected.POST("", streamHandler.CreateStream)
	protected.GET("", streamHandler.GetStreams)
	protected.GET("/live", streamHandler.GetLiveStreams)
	protected.GET("/:id", streamHandler.GetStream)
	protected.PUT("/:id/start", streamHandler.StartStream)
	protected.PUT("/:id/end", streamHandler.EndStream)
	protected.PUT("/:id", streamHandler.UpdateStreamInfo)
	protected.DELETE("/:id", streamHandler.DeleteStream)

	// Public routes (no authentication required)
	public := e.Group("/api/v1/streams")
	public.GET("/live/public", streamHandler.GetLiveStreams)
	public.GET("/:id/public", streamHandler.GetStream)

	// Internal routes for RTMP server integration
	internal := e.Group("/api/v1/internal/streams")
	internal.PUT("/:id/viewer-count", streamHandler.UpdateStreamViewerCount)

	// Statistics route
	stats := e.Group("/api/v1/stats")
	stats.GET("/streams", streamHandler.GetStreamStatistics)

	utils.Logger.Info("Setting up stream API routes under /api/v1/streams")
}
