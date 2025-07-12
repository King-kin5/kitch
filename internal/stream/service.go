package stream

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	utils "kitch/pkg/utils"
	"strings"
	"time"

	"github.com/google/uuid"
)

type StreamService struct {
	store StreamStore
}

func NewStreamService(store StreamStore) *StreamService {
	return &StreamService{
		store: store,
	}
}

// Stream Key Management

// GenerateStreamKey creates a new stream key for a user
func (ss *StreamService) GenerateStreamKey(userID uuid.UUID, name string) (*StreamKey, error) {
	// Validate input
	if name == "" {
		name = "Default Stream Key"
	}

	name = strings.TrimSpace(name)
	if len(name) > 100 {
		return nil, fmt.Errorf("stream key name too long")
	}

	// Check if user has too many active stream keys (rate limiting)
	existingKeys, err := ss.store.GetStreamKeysByUserID(userID)
	if err != nil {
		utils.Logger.Errorf("Failed to check existing stream keys: %v", err)
		return nil, fmt.Errorf("failed to check existing stream keys")
	}

	activeCount := 0
	for _, key := range existingKeys {
		if key.IsActive {
			activeCount++
		}
	}

	// Limit to 10 active stream keys per user
	if activeCount >= 10 {
		return nil, fmt.Errorf("maximum number of active stream keys reached (10)")
	}

	// Generate a secure random stream key
	keyValue, err := ss.generateSecureKey()
	if err != nil {
		utils.Logger.Errorf("Failed to generate stream key: %v", err)
		return nil, fmt.Errorf("failed to generate stream key")
	}

	streamKey := &StreamKey{
		ID:       uuid.New(),
		UserID:   userID,
		KeyValue: keyValue,
		Name:     name,
		IsActive: true,
	}

	err = ss.store.CreateStreamKey(streamKey)
	if err != nil {
		utils.Logger.Errorf("Failed to create stream key in database: %v", err)
		return nil, fmt.Errorf("failed to create stream key")
	}

	utils.Logger.Infof("Generated stream key for user %s: %s", userID, streamKey.ID)
	return streamKey, nil
}

// generateSecureKey generates a cryptographically secure random key
func (ss *StreamService) generateSecureKey() (string, error) {
	bytes := make([]byte, 32) // 256 bits
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// GetStreamKeysByUser retrieves all stream keys for a user
func (ss *StreamService) GetStreamKeysByUser(userID uuid.UUID) ([]*StreamKey, error) {
	streamKeys, err := ss.store.GetStreamKeysByUserID(userID)
	if err != nil {
		utils.Logger.Errorf("Failed to get stream keys for user %s: %v", userID, err)
		return nil, fmt.Errorf("failed to get stream keys")
	}

	return streamKeys, nil
}

// ValidateStreamKey validates a stream key and returns the associated stream key record
func (ss *StreamService) ValidateStreamKey(keyValue string) (*StreamKey, error) {
	streamKey, err := ss.store.GetStreamKeyByValue(keyValue)
	if err != nil {
		utils.Logger.Errorf("Failed to validate stream key: %v", err)
		return nil, fmt.Errorf("failed to validate stream key")
	}

	if streamKey == nil {
		return nil, fmt.Errorf("invalid stream key")
	}

	if !streamKey.IsActive {
		return nil, fmt.Errorf("stream key is inactive")
	}

	// Update last used timestamp
	err = ss.store.UpdateStreamKeyLastUsed(streamKey.ID)
	if err != nil {
		utils.Logger.Errorf("Failed to update stream key last used: %v", err)
		// Don't return error here as the validation was successful
	}

	return streamKey, nil
}

// DeactivateStreamKey deactivates a stream key
func (ss *StreamService) DeactivateStreamKey(keyID uuid.UUID, userID uuid.UUID) error {
	streamKey, err := ss.store.GetStreamKeyByID(keyID)
	if err != nil {
		utils.Logger.Errorf("Failed to get stream key: %v", err)
		return fmt.Errorf("failed to get stream key")
	}

	if streamKey == nil {
		return fmt.Errorf("stream key not found")
	}

	if streamKey.UserID != userID {
		return fmt.Errorf("unauthorized access to stream key")
	}

	err = ss.store.DeactivateStreamKey(keyID)
	if err != nil {
		utils.Logger.Errorf("Failed to deactivate stream key: %v", err)
		return fmt.Errorf("failed to deactivate stream key")
	}

	utils.Logger.Infof("Deactivated stream key %s for user %s", keyID, userID)
	return nil
}

// DeleteStreamKey deletes a stream key
func (ss *StreamService) DeleteStreamKey(keyID uuid.UUID, userID uuid.UUID) error {
	streamKey, err := ss.store.GetStreamKeyByID(keyID)
	if err != nil {
		utils.Logger.Errorf("Failed to get stream key: %v", err)
		return fmt.Errorf("failed to get stream key")
	}

	if streamKey == nil {
		return fmt.Errorf("stream key not found")
	}

	if streamKey.UserID != userID {
		return fmt.Errorf("unauthorized access to stream key")
	}

	err = ss.store.DeleteStreamKey(keyID)
	if err != nil {
		utils.Logger.Errorf("Failed to delete stream key: %v", err)
		return fmt.Errorf("failed to delete stream key")
	}

	utils.Logger.Infof("Deleted stream key %s for user %s", keyID, userID)
	return nil
}

// Stream Management

// CreateStream creates a new stream for a user
func (ss *StreamService) CreateStream(userID uuid.UUID, streamKeyID uuid.UUID, title, description, category string) (*Stream, error) {
	// Validate that the stream key belongs to the user
	streamKey, err := ss.store.GetStreamKeyByID(streamKeyID)
	if err != nil {
		utils.Logger.Errorf("Failed to get stream key: %v", err)
		return nil, fmt.Errorf("failed to get stream key")
	}

	if streamKey == nil {
		return nil, fmt.Errorf("stream key not found")
	}

	if streamKey.UserID != userID {
		return nil, fmt.Errorf("unauthorized access to stream key")
	}

	if !streamKey.IsActive {
		return nil, fmt.Errorf("stream key is inactive")
	}

	// Clean up input strings
	title = strings.TrimSpace(title)
	if title == "" {
		return nil, fmt.Errorf("stream title is required")
	}

	if len(title) > 200 {
		return nil, fmt.Errorf("stream title too long")
	}

	description = strings.TrimSpace(description)
	if len(description) > 2000 {
		return nil, fmt.Errorf("stream description too long")
	}

	category = strings.TrimSpace(category)
	if len(category) > 100 {
		return nil, fmt.Errorf("stream category too long")
	}

	// Check if user has too many active streams (rate limiting)
	existingStreams, err := ss.store.GetStreamsByUserID(userID)
	if err != nil {
		utils.Logger.Errorf("Failed to check existing streams: %v", err)
		return nil, fmt.Errorf("failed to check existing streams")
	}

	activeCount := 0
	for _, stream := range existingStreams {
		if stream.IsLive {
			activeCount++
		}
	}

	// Limit to 5 active streams per user
	if activeCount >= 5 {
		return nil, fmt.Errorf("maximum number of active streams reached (5)")
	}

	stream := &Stream{
		ID:          uuid.New(),
		UserID:      userID,
		StreamKeyID: streamKeyID,
		Title:       title,
		Description: &description,
		Category:    &category,
		IsLive:      false,
		ViewerCount: 0,
	}

	err = ss.store.CreateStream(stream)
	if err != nil {
		utils.Logger.Errorf("Failed to create stream: %v", err)
		return nil, fmt.Errorf("failed to create stream")
	}

	utils.Logger.Infof("Created stream %s for user %s", stream.ID, userID)
	return stream, nil
}

// GetStreamsByUser retrieves all streams for a user
func (ss *StreamService) GetStreamsByUser(userID uuid.UUID) ([]*Stream, error) {
	streams, err := ss.store.GetStreamsByUserID(userID)
	if err != nil {
		utils.Logger.Errorf("Failed to get streams for user %s: %v", userID, err)
		return nil, fmt.Errorf("failed to get streams")
	}

	return streams, nil
}

// GetLiveStreams retrieves all currently live streams
func (ss *StreamService) GetLiveStreams() ([]*Stream, error) {
	streams, err := ss.store.GetLiveStreams()
	if err != nil {
		utils.Logger.Errorf("Failed to get live streams: %v", err)
		return nil, fmt.Errorf("failed to get live streams")
	}

	return streams, nil
}

// GetStreamByID retrieves a specific stream by ID
func (ss *StreamService) GetStreamByID(streamID uuid.UUID) (*Stream, error) {
	stream, err := ss.store.GetStreamByID(streamID)
	if err != nil {
		utils.Logger.Errorf("Failed to get stream %s: %v", streamID, err)
		return nil, fmt.Errorf("failed to get stream")
	}

	if stream == nil {
		return nil, fmt.Errorf("stream not found")
	}

	return stream, nil
}

// GetStreamKeyByID retrieves a specific stream key by ID
func (ss *StreamService) GetStreamKeyByID(keyID uuid.UUID) (*StreamKey, error) {
	streamKey, err := ss.store.GetStreamKeyByID(keyID)
	if err != nil {
		utils.Logger.Errorf("Failed to get stream key %s: %v", keyID, err)
		return nil, fmt.Errorf("failed to get stream key")
	}
	return streamKey, nil
}

// StartStream starts a stream (marks it as live)
func (ss *StreamService) StartStream(streamID uuid.UUID, userID uuid.UUID) error {
	stream, err := ss.store.GetStreamByID(streamID)
	if err != nil {
		utils.Logger.Errorf("Failed to get stream: %v", err)
		return fmt.Errorf("failed to get stream")
	}

	if stream == nil {
		return fmt.Errorf("stream not found")
	}

	if stream.UserID != userID {
		return fmt.Errorf("unauthorized access to stream")
	}

	if stream.IsLive {
		return fmt.Errorf("stream is already live")
	}

	err = ss.store.StartStream(streamID)
	if err != nil {
		utils.Logger.Errorf("Failed to start stream: %v", err)
		return fmt.Errorf("failed to start stream")
	}

	utils.Logger.Infof("Started stream %s for user %s", streamID, userID)
	return nil
}

// EndStream ends a stream (marks it as not live)
func (ss *StreamService) EndStream(streamID uuid.UUID, userID uuid.UUID) error {
	stream, err := ss.store.GetStreamByID(streamID)
	if err != nil {
		utils.Logger.Errorf("Failed to get stream: %v", err)
		return fmt.Errorf("failed to get stream")
	}

	if stream == nil {
		return fmt.Errorf("stream not found")
	}

	if stream.UserID != userID {
		return fmt.Errorf("unauthorized access to stream")
	}

	if !stream.IsLive {
		return fmt.Errorf("stream is not live")
	}

	err = ss.store.EndStream(streamID)
	if err != nil {
		utils.Logger.Errorf("Failed to end stream: %v", err)
		return fmt.Errorf("failed to end stream")
	}

	utils.Logger.Infof("Ended stream %s for user %s", streamID, userID)
	return nil
}

// UpdateStreamViewerCount updates the viewer count for a stream
func (ss *StreamService) UpdateStreamViewerCount(streamID uuid.UUID, viewerCount int) error {
	if viewerCount < 0 {
		return fmt.Errorf("viewer count cannot be negative")
	}

	// Validate that the stream exists and is live
	stream, err := ss.store.GetStreamByID(streamID)
	if err != nil {
		utils.Logger.Errorf("Failed to get stream for viewer count update: %v", err)
		return fmt.Errorf("failed to get stream")
	}

	if stream == nil {
		return fmt.Errorf("stream not found")
	}

	if !stream.IsLive {
		utils.Logger.Warnf("Attempted to update viewer count for non-live stream %s", streamID)
		// Don't return error, just set to 0 for non-live streams
		viewerCount = 0
	}

	err = ss.store.UpdateStreamViewerCount(streamID, viewerCount)
	if err != nil {
		utils.Logger.Errorf("Failed to update stream viewer count: %v", err)
		return fmt.Errorf("failed to update stream viewer count")
	}

	return nil
}

// UpdateStreamInfo updates stream information
func (ss *StreamService) UpdateStreamInfo(streamID uuid.UUID, userID uuid.UUID, title, description, category *string) error {
	stream, err := ss.store.GetStreamByID(streamID)
	if err != nil {
		utils.Logger.Errorf("Failed to get stream: %v", err)
		return fmt.Errorf("failed to get stream")
	}

	if stream == nil {
		return fmt.Errorf("stream not found")
	}

	if stream.UserID != userID {
		return fmt.Errorf("unauthorized access to stream")
	}

	// Clean up input strings
	if title != nil {
		*title = strings.TrimSpace(*title)
		if *title == "" {
			return fmt.Errorf("stream title cannot be empty")
		}
	}

	if description != nil {
		*description = strings.TrimSpace(*description)
	}

	if category != nil {
		*category = strings.TrimSpace(*category)
	}

	err = ss.store.UpdateStreamInfo(streamID, title, description, category)
	if err != nil {
		utils.Logger.Errorf("Failed to update stream info: %v", err)
		return fmt.Errorf("failed to update stream info")
	}

	utils.Logger.Infof("Updated stream info for stream %s", streamID)
	return nil
}

// DeleteStream deletes a stream
func (ss *StreamService) DeleteStream(streamID uuid.UUID, userID uuid.UUID) error {
	stream, err := ss.store.GetStreamByID(streamID)
	if err != nil {
		utils.Logger.Errorf("Failed to get stream: %v", err)
		return fmt.Errorf("failed to get stream")
	}

	if stream == nil {
		return fmt.Errorf("stream not found")
	}

	if stream.UserID != userID {
		return fmt.Errorf("unauthorized access to stream")
	}

	err = ss.store.DeleteStream(streamID)
	if err != nil {
		utils.Logger.Errorf("Failed to delete stream: %v", err)
		return fmt.Errorf("failed to delete stream")
	}

	utils.Logger.Infof("Deleted stream %s for user %s", streamID, userID)
	return nil
}

// Utility Methods

// GetStreamStatistics returns stream statistics
func (ss *StreamService) GetStreamStatistics() (map[string]interface{}, error) {
	totalStreams, err := ss.store.GetStreamCount()
	if err != nil {
		utils.Logger.Errorf("Failed to get stream count: %v", err)
		return nil, fmt.Errorf("failed to get stream statistics")
	}

	liveStreams, err := ss.store.GetLiveStreamCount()
	if err != nil {
		utils.Logger.Errorf("Failed to get live stream count: %v", err)
		return nil, fmt.Errorf("failed to get stream statistics")
	}

	stats := map[string]interface{}{
		"total_streams": totalStreams,
		"live_streams":  liveStreams,
		"timestamp":     time.Now().UTC(),
	}

	return stats, nil
}
