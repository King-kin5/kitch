package rtmp

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

type Handler struct {
	server *Server
}

func NewHandler(server *Server) *Handler {
	return &Handler{
		server: server,
	}
}

// GetStatus returns the RTMP server status
func (h *Handler) GetStatus(c echo.Context) error {
	stats := h.server.GetStats()
	return c.JSON(http.StatusOK, map[string]interface{}{
		"status": "running",
		"type":   "joy5",
		"stats":  stats,
		"config": h.server.GetConfig(),
	})
}

// GetStreams returns all active streams
func (h *Handler) GetStreams(c echo.Context) error {
	streams := make(map[string]interface{})

	// Get all streams from the server
	// This is a simplified version - you might want to add pagination
	for id, stream := range h.server.streams {
		streams[id] = map[string]interface{}{
			"id":       stream.ID,
			"is_live":  stream.IsLive,
			"viewers":  stream.Viewers,
			"metadata": stream.Metadata,
		}
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"streams": streams,
		"count":   len(streams),
	})
}

// GetStream returns a specific stream by ID
func (h *Handler) GetStream(c echo.Context) error {
	streamID := c.Param("id")

	stream, exists := h.server.GetStream(streamID)
	if !exists {
		return c.JSON(http.StatusNotFound, map[string]interface{}{
			"error": "Stream not found",
		})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"id":       stream.ID,
		"is_live":  stream.IsLive,
		"viewers":  stream.Viewers,
		"metadata": stream.Metadata,
	})
}

// GetConnections returns all active connections
func (h *Handler) GetConnections(c echo.Context) error {
	connections := h.server.GetConnections()

	connList := make([]map[string]interface{}, 0, len(connections))
	for id, conn := range connections {
		connList = append(connList, map[string]interface{}{
			"id":          id,
			"remote_addr": conn.Conn.RemoteAddr().String(),
			"type":        conn.Type,
			"stream_id":   conn.StreamID,
			"start_time":  conn.StartTime,
		})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"connections": connList,
		"count":       len(connList),
	})
}

// UpdateConfig updates the RTMP server configuration
func (h *Handler) UpdateConfig(c echo.Context) error {
	var config Config
	if err := c.Bind(&config); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{
			"error": "Invalid configuration format",
		})
	}

	h.server.SetConfig(&config)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "Configuration updated successfully",
		"config":  config,
	})
}
