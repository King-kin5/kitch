package stream

import (
	"time"

	"github.com/google/uuid"
)

type StreamKey struct {
	ID         uuid.UUID  `json:"id" db:"id"`
	UserID     uuid.UUID  `json:"user_id" db:"user_id"`
	KeyValue   string     `json:"key_value" db:"key_value"`
	Name       string     `json:"name" db:"name"`
	IsActive   bool       `json:"is_active" db:"is_active"`
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at" db:"last_used_at"`
}

type Stream struct {
	ID           uuid.UUID  `json:"id" db:"id"`
	UserID       uuid.UUID  `json:"user_id" db:"user_id"`
	StreamKeyID  uuid.UUID  `json:"stream_key_id" db:"stream_key_id"`
	Title        string     `json:"title" db:"title"`
	Description  *string    `json:"description" db:"description"`
	Category     *string    `json:"category" db:"category"`
	IsLive       bool       `json:"is_live" db:"is_live"`
	ViewerCount  int        `json:"viewer_count" db:"viewer_count"`
	StartedAt    *time.Time `json:"started_at" db:"started_at"`
	EndedAt      *time.Time `json:"ended_at" db:"ended_at"`
	ThumbnailURL *string    `json:"thumbnail_url" db:"thumbnail_url"`
	RTMPURL      *string    `json:"rtmp_url" db:"rtmp_url"`
	HLSUrl       *string    `json:"hls_url" db:"hls_url"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at" db:"updated_at"`
}
