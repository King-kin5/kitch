package rtmp

import (
	"fmt"
	"kitch/internal/stream"
)

type RTMPDatastore struct {
	StreamStore stream.StreamStore
}

// ValidateStreamKey checks if the stream key is valid and returns RTMP StreamInfo
func (ds *RTMPDatastore) ValidateStreamKey(streamKey string) (*StreamInfo, error) {
	key, err := ds.StreamStore.GetStreamKeyByValue(streamKey)
	if err != nil {
		return nil, fmt.Errorf("error checking stream key: %w", err)
	}
	if key == nil || !key.IsActive {
		return nil, fmt.Errorf("invalid or inactive stream key")
	}

	// Optionally, get the latest stream for this user (if you want to attach stream info)
	streams, err := ds.StreamStore.GetStreamsByUserID(key.UserID)
	if err != nil {
		return nil, fmt.Errorf("error fetching streams for user: %w", err)
	}

	var latestStreamTitle, latestStreamCategory, latestStreamDescription string
	if len(streams) > 0 {
		latest := streams[0]
		latestStreamTitle = latest.Title
		if latest.Category != nil {
			latestStreamCategory = *latest.Category
		}
		if latest.Description != nil {
			latestStreamDescription = *latest.Description
		}
	}

	return &StreamInfo{
		ID:          key.ID.String(),
		StreamKey:   key.KeyValue,
		UserID:      key.UserID.String(),
		Title:       latestStreamTitle,
		Description: latestStreamDescription,
		Category:    latestStreamCategory,
		CreatedAt:   key.CreatedAt,
		UpdatedAt:   key.CreatedAt,
	}, nil
}
