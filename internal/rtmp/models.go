package rtmp

import (
	"context"
	utils "kitch/pkg/utils"
	"net"
	"sync"
	"time"

	"github.com/nareix/joy5/format/rtmp"
)

// StreamValidator interface for validating stream keys
type StreamValidator interface {
	ValidateStreamKey(streamKey string) (*StreamInfo, error)
	UpdateStreamStatus(streamKey string, isLive bool) error
}

// DatabaseStreamValidator implements StreamValidator using a database
type DatabaseStreamValidator struct {
	Datastore *RTMPDatastore
}

func (v *DatabaseStreamValidator) ValidateStreamKey(streamKey string) (*StreamInfo, error) {
	return v.Datastore.ValidateStreamKey(streamKey)
}

func (v *DatabaseStreamValidator) UpdateStreamStatus(streamKey string, isLive bool) error {
	// TODO: Implement database update
	utils.Logger.Infof("Stream status updated: %s, live: %t", streamKey, isLive)
	return nil
}

// StreamInfo contains metadata about a stream
// Only fields tracked in the schema and used in production are included
type StreamInfo struct {
	ID          string    `json:"id"`
	StreamKey   string    `json:"stream_key"`
	UserID      string    `json:"user_id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Category    string    `json:"category"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// StreamStatus represents the current status of a stream
type StreamStatus struct {
	StreamKey     string                 `json:"stream_key"`
	IsLive        bool                   `json:"is_live"`
	StartTime     *time.Time             `json:"start_time,omitempty"`
	EndTime       *time.Time             `json:"end_time,omitempty"`
	ViewerCount   int                    `json:"viewer_count"`
	ConnectionID  string                 `json:"connection_id"`
	PublisherIP   string                 `json:"publisher_ip"`
	Bitrate       int                    `json:"bitrate"`
	Resolution    string                 `json:"resolution"`
	FPS           int                    `json:"fps"`
	Codec         string                 `json:"codec"`
	Metadata      map[string]interface{} `json:"metadata"`
	LastHeartbeat time.Time              `json:"last_heartbeat"`
}

type Server struct {
	port        int
	listener    net.Listener
	rtmpSrv     *rtmp.Server
	connections map[string]*Connection
	streams     map[string]*StreamStatus
	validator   StreamValidator
	mu          sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	config      *Config
	startTime   time.Time // Added for uptime tracking
}

type Config struct {
	Port              int
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	MaxConnections    int
	BufferSize        int
	HeartbeatTimeout  time.Duration
	MaxStreamDuration time.Duration
	RequireAuth       bool
}

// Stream struct for RTMP, matching the database-backed Stream struct
// Only add RTMP-specific fields if absolutely necessary
type Stream struct {
	ID           string     `json:"id"`
	UserID       string     `json:"user_id"`
	StreamKeyID  string     `json:"stream_key_id"`
	Title        string     `json:"title"`
	Description  string     `json:"description"`
	Category     string     `json:"category"`
	IsLive       bool       `json:"is_live"`
	ViewerCount  int        `json:"viewer_count"`
	StartedAt    *time.Time `json:"started_at"`
	EndedAt      *time.Time `json:"ended_at"`
	ThumbnailURL string     `json:"thumbnail_url"`
	RTMPURL      string     `json:"rtmp_url"`
	HLSUrl       string     `json:"hls_url"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

type Connection struct {
	ID        string
	Conn      net.Conn
	Type      string // "publisher" or "subscriber"
	StreamKey string
	StreamID  string
	StartTime time.Time
	LastPing  time.Time
	UserAgent string
	RemoteIP  string
}
