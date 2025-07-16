package rtmp

import (
	"net/http"
	"strconv"
	"time"
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
// GetStatus returns comprehensive RTMP server status
func (h *Handler) GetStatus(c echo.Context) error {
	stats := h.server.GetStats()
	return c.JSON(http.StatusOK, map[string]interface{}{
		"status":    "running",
		"type":      "joy5-enhanced",
		"timestamp": time.Now().Unix(),
		"stats":     stats,
		"config":    h.server.GetConfig(),
	})
}
// GetStreams returns all streams with optional filtering
func (h *Handler) GetStreams(c echo.Context) error {
	liveOnly := c.QueryParam("live") == "true"
	var streams map[string]*StreamStatus
	if liveOnly {
		streams = h.server.GetLiveStreams()
	} else {
		streams = h.server.GetAllStreams()
	}
	// Transform to response format
	streamList := make([]map[string]interface{}, 0, len(streams))
	for streamKey, status := range streams {
		streamData := map[string]interface{}{
			"stream_key":     streamKey,
			"is_live":        status.IsLive,
			"viewer_count":   status.ViewerCount,
			"start_time":     status.StartTime,
			"end_time":       status.EndTime,
			"connection_id":  status.ConnectionID,
			"publisher_ip":   status.PublisherIP,
			"bitrate":        status.Bitrate,
			"resolution":     status.Resolution,
			"fps":            status.FPS,
			"codec":          status.Codec,
			"metadata":       status.Metadata,
			"last_heartbeat": status.LastHeartbeat,
		}
		streamList = append(streamList, streamData)
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"streams": streamList,
		"count":   len(streamList),
		"filter":  map[string]interface{}{
			"live_only": liveOnly,
		},
	})
}
// GetStream returns a specific stream by stream key
func (h *Handler) GetStream(c echo.Context) error {
	streamKey := c.Param("key")
	if streamKey == "" {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{
			"error": "Stream key is required",
		})
	}
	streamStatus, exists := h.server.GetStreamStatus(streamKey)
	if !exists {
		return c.JSON(http.StatusNotFound, map[string]interface{}{
			"error": "Stream not found",
		})
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"stream_key":     streamKey,
		"is_live":        streamStatus.IsLive,
		"viewer_count":   streamStatus.ViewerCount,
		"start_time":     streamStatus.StartTime,
		"end_time":       streamStatus.EndTime,
		"connection_id":  streamStatus.ConnectionID,
		"publisher_ip":   streamStatus.PublisherIP,
		"bitrate":        streamStatus.Bitrate,
		"resolution":     streamStatus.Resolution,
		"fps":            streamStatus.FPS,
		"codec":          streamStatus.Codec,
		"metadata":       streamStatus.Metadata,
		"last_heartbeat": streamStatus.LastHeartbeat,
	})
}
// GetConnections returns all active connections with pagination
func (h *Handler) GetConnections(c echo.Context) error {
	page := 1
	limit := 50
	if p := c.QueryParam("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}
	if l := c.QueryParam("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}
	allConnections := h.server.GetConnections()
	// Simple pagination
	start := (page - 1) * limit
	end := start + limit
	connList := make([]map[string]interface{}, 0)
	i := 0
	for id, conn := range allConnections {
		if i >= start && i < end {
			connData := map[string]interface{}{
				"id":           id,
				"remote_ip":    conn.RemoteIP,
				"type":         conn.Type,
				"stream_key":   conn.StreamKey,
				"stream_id":    conn.StreamID,
				"start_time":   conn.StartTime,
				"last_ping":    conn.LastPing,
				"user_agent":   conn.UserAgent,
			}
			connList = append(connList, connData)
		}
		i++
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"connections": connList,
		"pagination": map[string]interface{}{
			"page":        page,
			"limit":       limit,
			"total":       len(allConnections),
			"total_pages": (len(allConnections) + limit - 1) / limit,
		},
	})
}
// UpdateStreamMetadata updates metadata for a specific stream
func (h *Handler) UpdateStreamMetadata(c echo.Context) error {
	streamKey := c.Param("key")
	if streamKey == "" {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{
			"error": "Stream key is required",
		})
	}
	var metadata map[string]interface{}
	if err := c.Bind(&metadata); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{
			"error": "Invalid metadata format",
		})
	}
	if err := h.server.UpdateStreamMetadata(streamKey, metadata); err != nil {
		return c.JSON(http.StatusNotFound, map[string]interface{}{
			"error": err.Error(),
		})
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"message":    "Stream metadata updated successfully",
		"stream_key": streamKey,
		"metadata":   metadata,
	})
}
// ValidateStreamKey validates a stream key without starting a stream
func (h *Handler) ValidateStreamKey(c echo.Context) error {
	streamKey := c.Param("key")
	if streamKey == "" {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{
			"error": "Stream key is required",
		})
	}
	streamInfo, err := h.server.validator.ValidateStreamKey(streamKey)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]interface{}{
			"error": "Invalid stream key",
			"valid": false,
		})
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"valid":       true,
		"stream_info": streamInfo,
	})
}
// GetStreamLogs returns logs for a specific stream (placeholder)
func (h *Handler) GetStreamLogs(c echo.Context) error {
	streamKey := c.Param("key")
	if streamKey == "" {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{
			"error": "Stream key is required",
		})
	}
	// TODO: Implement actual log retrieval from database or log files
	// This is a placeholder implementation
	logs := []map[string]interface{}{
		{
			"timestamp": time.Now().Add(-5 * time.Minute).Unix(),
			"level":     "info",
			"message":   "Stream started",
			"metadata":  map[string]interface{}{"bitrate": 2500},
		},
		{
			"timestamp": time.Now().Add(-3 * time.Minute).Unix(),
			"level":     "info",
			"message":   "First viewer connected",
			"metadata":  map[string]interface{}{"viewer_count": 1},
		},
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"stream_key": streamKey,
		"logs":       logs,
		"count":      len(logs),
	})
}
// KillStream forcefully terminates a stream
func (h *Handler) KillStream(c echo.Context) error {
	streamKey := c.Param("key")
	if streamKey == "" {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{
			"error": "Stream key is required",
		})
	}
	// Check if stream exists and is live
	streamStatus, exists := h.server.GetStreamStatus(streamKey)
	if !exists {
		return c.JSON(http.StatusNotFound, map[string]interface{}{
			"error": "Stream not found",
		})
	}
	if !streamStatus.IsLive {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{
			"error": "Stream is not live",
		})
	}
	// TODO: Implement actual stream termination
	// This would involve closing the connection associated with the stream
	h.server.handleStreamEnd(streamKey)
	return c.JSON(http.StatusOK, map[string]interface{}{
		"message":    "Stream terminated successfully",
		"stream_key": streamKey,
	})
}
// GetStreamStats returns detailed statistics for a stream
func (h *Handler) GetStreamStats(c echo.Context) error {
	streamKey := c.Param("key")
	if streamKey == "" {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{
			"error": "Stream key is required",
		})
	}
	streamStatus, exists := h.server.GetStreamStatus(streamKey)
	if !exists {
		return c.JSON(http.StatusNotFound, map[string]interface{}{
			"error": "Stream not found",
		})
	}
	var duration int64
	if streamStatus.StartTime != nil {
		if streamStatus.EndTime != nil {
			duration = streamStatus.EndTime.Sub(*streamStatus.StartTime).Milliseconds()
		} else if streamStatus.IsLive {
			duration = time.Since(*streamStatus.StartTime).Milliseconds()
		}
	}
	stats := map[string]interface{}{
		"stream_key":     streamKey,
		"is_live":        streamStatus.IsLive,
		"viewer_count":   streamStatus.ViewerCount,
		"duration_ms":    duration,
		"start_time":     streamStatus.StartTime,
		"end_time":       streamStatus.EndTime,
		"publisher_ip":   streamStatus.PublisherIP,
		"connection_id":  streamStatus.ConnectionID,
		"bitrate":        streamStatus.Bitrate,
		"resolution":     streamStatus.Resolution,
		"fps":            streamStatus.FPS,
		"codec":          streamStatus.Codec,
		"last_heartbeat": streamStatus.LastHeartbeat,
		"metadata":       streamStatus.Metadata,
	}
	return c.JSON(http.StatusOK, stats)
}
// UpdateConfig updates the RTMP server configuration
func (h *Handler) UpdateConfig(c echo.Context) error {
	var config Config
	if err := c.Bind(&config); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{
			"error": "Invalid configuration format",
		})
	}
	// Validate configuration
	if config.Port <= 0 || config.Port > 65535 {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{
			"error": "Invalid port number",
		})
	}
	if config.MaxConnections <= 0 {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{
			"error": "Max connections must be positive",
		})
	}
	if config.ReadTimeout <= 0 {
		config.ReadTimeout = 30 * time.Second
	}
	if config.WriteTimeout <= 0 {
		config.WriteTimeout = 30 * time.Second
	}
	if config.HeartbeatTimeout <= 0 {
		config.HeartbeatTimeout = 60 * time.Second
	}
	h.server.SetConfig(&config)
	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "Configuration updated successfully",
		"config":  config,
	})
}
// GetHealth returns server health status
func (h *Handler) GetHealth(c echo.Context) error {
	stats := h.server.GetStats()
	// Simple health check based on connection count and active streams
	healthy := true
	var issues []string
	serverStats := stats["server"].(map[string]interface{})
	streamStats := stats["streams"].(map[string]interface{})
	currentConnections := serverStats["connections"].(int)
	maxConnections := serverStats["max_connections"].(int)
	// Check connection usage
	if float64(currentConnections)/float64(maxConnections) > 0.9 {
		healthy = false
		issues = append(issues, "High connection usage")
	}
	// Check for any stalled streams (placeholder logic)
	liveStreams := streamStats["live"].(int)
	if liveStreams > 100 { // Arbitrary threshold
		issues = append(issues, "High number of live streams")
	}
	status := "healthy"
	if !healthy {
		status = "degraded"
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"status":    status,
		"healthy":   healthy,
		"timestamp": time.Now().Unix(),
		"issues":    issues,
		"stats":     stats,
	})
}
// GetMetrics returns metrics in a format suitable for monitoring systems
func (h *Handler) GetMetrics(c echo.Context) error {
	stats := h.server.GetStats()
	connections := h.server.GetConnections()
	// Calculate additional metrics
	var publisherCount, subscriberCount int
	for _, conn := range connections {
		switch conn.Type {
		case "publisher":
			publisherCount++
		case "subscriber":
			subscriberCount++
		}
	}
	serverStats := stats["server"].(map[string]interface{})
	streamStats := stats["streams"].(map[string]interface{})
	metrics := map[string]interface{}{
		"rtmp_server_connections_total":     serverStats["connections"],
		"rtmp_server_connections_max":       serverStats["max_connections"],
		"rtmp_server_streams_total":         streamStats["total"],
		"rtmp_server_streams_live":          streamStats["live"],
		"rtmp_server_viewers_total":         streamStats["total_viewers"],
		"rtmp_server_publishers_total":      publisherCount,
		"rtmp_server_subscribers_total":     subscriberCount,
		"rtmp_server_port":                  h.server.port,
		"rtmp_server_uptime_seconds":        time.Since(time.Now()).Seconds(), // You'd want to track actual uptime
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"metrics":   metrics,
		"timestamp": time.Now().Unix(),
	})
}