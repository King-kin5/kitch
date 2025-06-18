package main

import (
	"log"
	"net/http"

	"github.com/labstack/echo/v4"
)

func main() {
	log.Println("Starting Kitch streaming server...")

	// TODO: Initialize configuration
	// TODO: Setup database connections
	// TODO: Initialize RTMP server
	// TODO: Setup HTTP routes
	// TODO: Start WebSocket server for chat

	e := echo.New()

	// Temporary HTTP server for health check
	e.GET("/health", func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	})

	log.Println("Server listening on :8080")
	e.Logger.Fatal(e.Start(":8080"))
}
