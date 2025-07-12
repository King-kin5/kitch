package stream

import (
	"net/http"
	"strconv"

	utils "kitch/pkg/utils"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type Handler struct {
	service *StreamService
}

func NewHandler(store StreamStore) *Handler {
	service := NewStreamService(store)
	return &Handler{
		service: service,
	}
}

// Stream Key Management Endpoints

// GenerateStreamKey generates a new stream key for the authenticated user
func (h *Handler) GenerateStreamKey(c echo.Context) error {
	userID, err := getUserIDFromContext(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "Unauthorized")
	}

	var request struct {
		Name string `json:"name"`
	}

	if err := c.Bind(&request); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}

	streamKey, err := h.service.GenerateStreamKey(userID, request.Name)
	if err != nil {
		utils.Logger.Errorf("Failed to generate stream key: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to generate stream key")
	}

	return c.JSON(http.StatusCreated, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"id":         streamKey.ID,
			"key_value":  streamKey.KeyValue,
			"name":       streamKey.Name,
			"is_active":  streamKey.IsActive,
			"created_at": streamKey.CreatedAt,
		},
	})
}

// GetStreamKeys retrieves all stream keys for the authenticated user
func (h *Handler) GetStreamKeys(c echo.Context) error {
	userID, err := getUserIDFromContext(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "Unauthorized")
	}

	streamKeys, err := h.service.GetStreamKeysByUser(userID)
	if err != nil {
		utils.Logger.Errorf("Failed to get stream keys: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get stream keys")
	}

	// Don't return the actual key values for security
	var safeStreamKeys []map[string]interface{}
	for _, key := range streamKeys {
		safeStreamKeys = append(safeStreamKeys, map[string]interface{}{
			"id":           key.ID,
			"name":         key.Name,
			"is_active":    key.IsActive,
			"last_used_at": key.LastUsedAt,
			"created_at":   key.CreatedAt,
		})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    safeStreamKeys,
	})
}

// GetStreamKey retrieves a specific stream key (without the actual key value)
func (h *Handler) GetStreamKey(c echo.Context) error {
	userID, err := getUserIDFromContext(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "Unauthorized")
	}

	keyID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid stream key ID")
	}

	streamKey, err := h.service.GetStreamKeyByID(keyID)
	if err != nil {
		utils.Logger.Errorf("Failed to get stream key: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get stream key")
	}

	if streamKey == nil {
		return echo.NewHTTPError(http.StatusNotFound, "Stream key not found")
	}

	if streamKey.UserID != userID {
		return echo.NewHTTPError(http.StatusForbidden, "Access denied")
	}

	// Don't return the actual key value for security
	return c.JSON(http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"id":           streamKey.ID,
			"name":         streamKey.Name,
			"is_active":    streamKey.IsActive,
			"last_used_at": streamKey.LastUsedAt,
			"created_at":   streamKey.CreatedAt,
		},
	})
}

// DeactivateStreamKey deactivates a stream key
func (h *Handler) DeactivateStreamKey(c echo.Context) error {
	userID, err := getUserIDFromContext(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "Unauthorized")
	}

	keyID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid stream key ID")
	}

	err = h.service.DeactivateStreamKey(keyID, userID)
	if err != nil {
		utils.Logger.Errorf("Failed to deactivate stream key: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to deactivate stream key")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Stream key deactivated successfully",
	})
}

// DeleteStreamKey deletes a stream key
func (h *Handler) DeleteStreamKey(c echo.Context) error {
	userID, err := getUserIDFromContext(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "Unauthorized")
	}

	keyID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid stream key ID")
	}

	err = h.service.DeleteStreamKey(keyID, userID)
	if err != nil {
		utils.Logger.Errorf("Failed to delete stream key: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to delete stream key")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Stream key deleted successfully",
	})
}

// Stream Management Endpoints

// CreateStream creates a new stream
func (h *Handler) CreateStream(c echo.Context) error {
	userID, err := getUserIDFromContext(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "Unauthorized")
	}

	var request struct {
		StreamKeyID string  `json:"stream_key_id"`
		Title       string  `json:"title"`
		Description *string `json:"description"`
		Category    *string `json:"category"`
	}

	if err := c.Bind(&request); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}

	streamKeyID, err := uuid.Parse(request.StreamKeyID)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid stream key ID")
	}

	stream, err := h.service.CreateStream(userID, streamKeyID, request.Title, *request.Description, *request.Category)
	if err != nil {
		utils.Logger.Errorf("Failed to create stream: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create stream")
	}

	return c.JSON(http.StatusCreated, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"id":           stream.ID,
			"title":        stream.Title,
			"description":  stream.Description,
			"category":     stream.Category,
			"is_live":      stream.IsLive,
			"viewer_count": stream.ViewerCount,
			"created_at":   stream.CreatedAt,
		},
	})
}

// GetStreams retrieves all streams for the authenticated user
func (h *Handler) GetStreams(c echo.Context) error {
	userID, err := getUserIDFromContext(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "Unauthorized")
	}

	streams, err := h.service.GetStreamsByUser(userID)
	if err != nil {
		utils.Logger.Errorf("Failed to get streams: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get streams")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    streams,
	})
}

// GetStream retrieves a specific stream
func (h *Handler) GetStream(c echo.Context) error {
	streamID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid stream ID")
	}

	stream, err := h.service.GetStreamByID(streamID)
	if err != nil {
		utils.Logger.Errorf("Failed to get stream: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get stream")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    stream,
	})
}

// GetLiveStreams retrieves all currently live streams
func (h *Handler) GetLiveStreams(c echo.Context) error {
	streams, err := h.service.GetLiveStreams()
	if err != nil {
		utils.Logger.Errorf("Failed to get live streams: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get live streams")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    streams,
	})
}

// StartStream starts a stream
func (h *Handler) StartStream(c echo.Context) error {
	userID, err := getUserIDFromContext(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "Unauthorized")
	}

	streamID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid stream ID")
	}

	err = h.service.StartStream(streamID, userID)
	if err != nil {
		utils.Logger.Errorf("Failed to start stream: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to start stream")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Stream started successfully",
	})
}

// EndStream ends a stream
func (h *Handler) EndStream(c echo.Context) error {
	userID, err := getUserIDFromContext(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "Unauthorized")
	}

	streamID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid stream ID")
	}

	err = h.service.EndStream(streamID, userID)
	if err != nil {
		utils.Logger.Errorf("Failed to end stream: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to end stream")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Stream ended successfully",
	})
}

// UpdateStreamInfo updates stream information
func (h *Handler) UpdateStreamInfo(c echo.Context) error {
	userID, err := getUserIDFromContext(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "Unauthorized")
	}

	streamID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid stream ID")
	}

	var request struct {
		Title       *string `json:"title"`
		Description *string `json:"description"`
		Category    *string `json:"category"`
	}

	if err := c.Bind(&request); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}

	err = h.service.UpdateStreamInfo(streamID, userID, request.Title, request.Description, request.Category)
	if err != nil {
		utils.Logger.Errorf("Failed to update stream info: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update stream info")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Stream info updated successfully",
	})
}

// DeleteStream deletes a stream
func (h *Handler) DeleteStream(c echo.Context) error {
	userID, err := getUserIDFromContext(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "Unauthorized")
	}

	streamID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid stream ID")
	}

	err = h.service.DeleteStream(streamID, userID)
	if err != nil {
		utils.Logger.Errorf("Failed to delete stream: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to delete stream")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Stream deleted successfully",
	})
}

// GetStreamStatistics returns stream statistics
func (h *Handler) GetStreamStatistics(c echo.Context) error {
	stats, err := h.service.GetStreamStatistics()
	if err != nil {
		utils.Logger.Errorf("Failed to get stream statistics: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get stream statistics")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    stats,
	})
}

// UpdateStreamViewerCount updates the viewer count for a stream (internal use)
func (h *Handler) UpdateStreamViewerCount(c echo.Context) error {
	streamID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid stream ID")
	}

	viewerCountStr := c.QueryParam("viewer_count")
	viewerCount, err := strconv.Atoi(viewerCountStr)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid viewer count")
	}

	err = h.service.UpdateStreamViewerCount(streamID, viewerCount)
	if err != nil {
		utils.Logger.Errorf("Failed to update stream viewer count: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update stream viewer count")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Viewer count updated successfully",
	})
}

// Helper function to get user ID from context
func getUserIDFromContext(c echo.Context) (uuid.UUID, error) {
	userIDStr := c.Get("user_id")
	if userIDStr == nil {
		return uuid.Nil, echo.NewHTTPError(http.StatusUnauthorized, "User ID not found in context")
	}

	userID, ok := userIDStr.(string)
	if !ok {
		return uuid.Nil, echo.NewHTTPError(http.StatusUnauthorized, "Invalid user ID in context")
	}

	parsedUserID, err := uuid.Parse(userID)
	if err != nil {
		return uuid.Nil, echo.NewHTTPError(http.StatusUnauthorized, "Invalid user ID format")
	}

	return parsedUserID, nil
}
