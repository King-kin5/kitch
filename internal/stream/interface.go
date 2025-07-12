package stream

import (
	"github.com/google/uuid"
)

// StreamStore defines the interface for stream and stream key operations
type StreamStore interface {
	// Stream Key Management
	CreateStreamKey(streamKey *StreamKey) error
	GetStreamKeyByID(id uuid.UUID) (*StreamKey, error)
	GetStreamKeyByValue(keyValue string) (*StreamKey, error)
	GetStreamKeysByUserID(userID uuid.UUID) ([]*StreamKey, error)
	UpdateStreamKeyLastUsed(id uuid.UUID) error
	DeactivateStreamKey(id uuid.UUID) error
	DeleteStreamKey(id uuid.UUID) error

	// Stream Management
	CreateStream(stream *Stream) error
	GetStreamByID(id uuid.UUID) (*Stream, error)
	GetStreamsByUserID(userID uuid.UUID) ([]*Stream, error)
	GetLiveStreams() ([]*Stream, error)
	StartStream(id uuid.UUID) error
	EndStream(id uuid.UUID) error
	UpdateStreamViewerCount(id uuid.UUID, viewerCount int) error
	UpdateStreamInfo(id uuid.UUID, title, description, category *string) error
	DeleteStream(id uuid.UUID) error

	// Utility Methods
	CheckDBConnection() error
	GetStreamCount() (int64, error)
	GetLiveStreamCount() (int64, error)
} 