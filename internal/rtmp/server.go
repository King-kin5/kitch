package rtmp

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	utils "kitch/pkg/utils"

	"github.com/nareix/joy5/format/rtmp"
)

type Server struct {
	port        int
	listener    net.Listener
	rtmpSrv     *rtmp.Server
	connections map[string]*Connection
	streams     map[string]*Stream
	mu          sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	config      *Config
}

type Config struct {
	Port           int
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	MaxConnections int
	BufferSize     int
}

type Stream struct {
	ID       string
	Key      string
	IsLive   bool
	Viewers  int
	Metadata map[string]interface{}
	mu       sync.RWMutex
}

type Connection struct {
	ID        string
	Conn      net.Conn
	Type      string // "publisher" or "viewer"
	StreamID  string
	StartTime time.Time
}

func NewServer(port int) *Server {
	ctx, cancel := context.WithCancel(context.Background())

	config := &Config{
		Port:           port,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
		MaxConnections: 1000,
		BufferSize:     4096,
	}

	server := &Server{
		port:        port,
		connections: make(map[string]*Connection),
		streams:     make(map[string]*Stream),
		ctx:         ctx,
		cancel:      cancel,
		config:      config,
	}

	// Create joy5 RTMP server
	rtmpSrv := rtmp.NewServer()
	rtmpSrv.HandleConn = server.handleRTMPConnection
	server.rtmpSrv = rtmpSrv

	return server
}

func (s *Server) Start() error {
	// Create TCP listener
	listener, err := net.Listen("tcp", ":"+strconv.Itoa(s.config.Port))
	if err != nil {
		return fmt.Errorf("failed to create RTMP listener: %w", err)
	}
	s.listener = listener

	utils.Logger.Infof("RTMP (joy5) server listening on port %d", s.config.Port)

	// Start connection handling loop
	s.wg.Add(1)
	go s.acceptConnections()

	// Start cleanup routine
	s.wg.Add(1)
	go s.cleanupRoutine()

	utils.Logger.Info("RTMP server started successfully (joy5)")
	return nil
}

func (s *Server) acceptConnections() {
	defer s.wg.Done()

	for {
		select {
		case <-s.ctx.Done():
			utils.Logger.Info("RTMP server stopping connection acceptance")
			return
		default:
			conn, err := s.listener.Accept()
			if err != nil {
				if s.ctx.Err() != nil {
					// Server is shutting down
					return
				}
				utils.Logger.Errorf("Error accepting RTMP connection: %v", err)
				continue
			}

			// Check connection limit
			s.mu.RLock()
			if len(s.connections) >= s.config.MaxConnections {
				s.mu.RUnlock()
				utils.Logger.Warnf("Connection limit reached (%d), rejecting connection", s.config.MaxConnections)
				conn.Close()
				continue
			}
			s.mu.RUnlock()

			utils.Logger.Infof("New RTMP connection from %s", conn.RemoteAddr().String())

			// Handle connection in goroutine
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.handleConnection(conn)
			}()
		}
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Set connection timeouts
	conn.SetReadDeadline(time.Now().Add(s.config.ReadTimeout))
	conn.SetWriteDeadline(time.Now().Add(s.config.WriteTimeout))

	// Create connection record
	connID := fmt.Sprintf("%s-%d", conn.RemoteAddr().String(), time.Now().UnixNano())
	connection := &Connection{
		ID:        connID,
		Conn:      conn,
		StartTime: time.Now(),
	}

	s.mu.Lock()
	s.connections[connID] = connection
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.connections, connID)
		s.mu.Unlock()
	}()

	// Use joy5 to handle RTMP protocol
	s.rtmpSrv.HandleNetConn(conn)
}

func (s *Server) handleRTMPConnection(rtmpConn *rtmp.Conn, netConn net.Conn) {
	utils.Logger.Infof("RTMP connection established: %s", netConn.RemoteAddr().String())

	// Create connection handler
	handler := NewConnectionHandler(rtmpConn, netConn, s)

	// Start the connection handler
	if err := handler.Start(); err != nil {
		utils.Logger.Errorf("Failed to start connection handler: %v", err)
		netConn.Close()
		return
	}

	// Store the connection handler
	connID := handler.connectionID
	s.mu.Lock()
	s.connections[connID] = &Connection{
		ID:        connID,
		Conn:      netConn,
		StartTime: time.Now(),
	}
	s.mu.Unlock()

	// Wait for the connection to finish
	<-handler.ctx.Done()

	utils.Logger.Infof("RTMP connection closed: %s", connID)
}

func (s *Server) cleanupRoutine() {
	defer s.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.cleanupInactiveConnections()
			s.cleanupInactiveStreams()
		}
	}
}

func (s *Server) cleanupInactiveConnections() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for id, conn := range s.connections {
		if now.Sub(conn.StartTime) > 5*time.Minute {
			utils.Logger.Infof("Cleaning up inactive connection: %s", id)
			conn.Conn.Close()
			delete(s.connections, id)
		}
	}
}

func (s *Server) cleanupInactiveStreams() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, stream := range s.streams {
		if !stream.IsLive && stream.Viewers == 0 {
			utils.Logger.Infof("Cleaning up inactive stream: %s", id)
			delete(s.streams, id)
		}
	}
}

func (s *Server) Stop() error {
	utils.Logger.Info("Stopping RTMP server (joy5)...")

	// Signal shutdown
	s.cancel()

	// Close listener
	if s.listener != nil {
		if err := s.listener.Close(); err != nil {
			utils.Logger.Errorf("Error closing RTMP listener: %v", err)
		}
	}

	// Close all active connections
	s.mu.Lock()
	for id, conn := range s.connections {
		utils.Logger.Infof("Closing connection: %s", id)
		conn.Conn.Close()
	}
	s.mu.Unlock()

	// Wait for all goroutines to finish
	s.wg.Wait()
	utils.Logger.Info("RTMP server stopped gracefully (joy5)")
	return nil
}

// GetStats returns server statistics
func (s *Server) GetStats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := map[string]interface{}{
		"port":            s.port,
		"connections":     len(s.connections),
		"streams":         len(s.streams),
		"live_streams":    0,
		"max_connections": s.config.MaxConnections,
	}

	for _, stream := range s.streams {
		if stream.IsLive {
			stats["live_streams"] = stats["live_streams"].(int) + 1
		}
	}

	return stats
}

// GetStream returns a stream by ID
func (s *Server) GetStream(streamID string) (*Stream, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stream, exists := s.streams[streamID]
	return stream, exists
}

// GetConnections returns all active connections
func (s *Server) GetConnections() map[string]*Connection {
	s.mu.RLock()
	defer s.mu.RUnlock()

	connections := make(map[string]*Connection)
	for id, conn := range s.connections {
		connections[id] = conn
	}
	return connections
}

// SetConfig updates server configuration
func (s *Server) SetConfig(config *Config) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config = config
}

// GetConfig returns current server configuration
func (s *Server) GetConfig() *Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config
}
