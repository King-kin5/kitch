// server.go - Fixed RTMP Server Implementation
package rtmp

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	utils "kitch/pkg/utils"

	"github.com/nareix/joy5/format/rtmp"
	"github.com/nareix/joy5/av"
)

func NewServer(port int, validator StreamValidator) *Server {
	ctx, cancel := context.WithCancel(context.Background())

	config := &Config{
		Port:              port,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		MaxConnections:    1000,
		BufferSize:        4096,
		HeartbeatTimeout:  60 * time.Second,
		MaxStreamDuration: 12 * time.Hour,
		RequireAuth:       true,
	}

	server := &Server{
		port:        port,
		connections: make(map[string]*Connection),
		streams:     make(map[string]*StreamStatus),
		validator:   validator,
		ctx:         ctx,
		cancel:      cancel,
		config:      config,
		startTime:   time.Now(),
	}

	// Create joy5 RTMP server with proper event handlers
	rtmpSrv := &rtmp.Server{}
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

	utils.Logger.Infof("RTMP server listening on port %d", s.config.Port)

	// Start connection handling loop
	s.wg.Add(1)
	go s.acceptConnections()

	// Start cleanup routine
	s.wg.Add(1)
	go s.cleanupRoutine()

	// Start heartbeat monitor
	s.wg.Add(1)
	go s.heartbeatMonitor()

	utils.Logger.Info("RTMP server started successfully")
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

// Fixed handleRTMPConnection signature to match joy5 API
func (s *Server) handleRTMPConnection(conn *rtmp.Conn, nc net.Conn) {
	remoteAddr := nc.RemoteAddr().String()
	utils.Logger.Infof("New RTMP connection from: %s", remoteAddr)
	
	// Generate connection ID
	connID := fmt.Sprintf("%s-%d", remoteAddr, time.Now().UnixNano())
	
	// Store the connection
	s.mu.Lock()
	s.connections[connID] = &Connection{
		ID:        connID,
		Conn:      nc,
		StartTime: time.Now(),
		LastPing:  time.Now(),
		RemoteIP:  strings.Split(remoteAddr, ":")[0],
	}
	s.mu.Unlock()
	
	// Handle the RTMP session
	s.handleRTMPSession(conn, nc, connID)
	
	// Cleanup connection
	s.mu.Lock()
	delete(s.connections, connID)
	s.mu.Unlock()
	
	utils.Logger.Infof("RTMP connection closed: %s", connID)
}

func (s *Server) handleRTMPSession(conn *rtmp.Conn, nc net.Conn, connID string) {
	defer func() {
		if r := recover(); r != nil {
			utils.Logger.Errorf("Panic in handleRTMPSession: %v", r)
		}
	}()

	// Get stream information
	streamKey := s.extractStreamKey(conn.URL.Path)
	if streamKey == "" {
		utils.Logger.Errorf("No stream key found in URL: %s", conn.URL.Path)
		return
	}

	// Determine if this is a publish or play connection
	// Check URL path or use connection state to determine type
	isPublish := strings.Contains(conn.URL.Path, "/live/") || strings.Contains(conn.URL.Path, "/publish/")
	
	if isPublish {
		s.handlePublish(conn, nc, streamKey, connID)
	} else {
		s.handlePlay(conn, nc, streamKey, connID)
	}
}

// handlePublish handles RTMP publish events (streaming starts)
func (s *Server) handlePublish(conn *rtmp.Conn, nc net.Conn, streamKey, connID string) {
	defer func() {
		if r := recover(); r != nil {
			utils.Logger.Errorf("Panic in handlePublish: %v", r)
		}
		s.handleStreamEnd(streamKey)
	}()

	utils.Logger.Infof("Publish request for stream key: %s", streamKey)

	// Validate stream key with authentication
	streamInfo, err := s.validator.ValidateStreamKey(streamKey)
	if err != nil {
		utils.Logger.Errorf("Invalid stream key %s: %v", streamKey, err)
		return
	}

	// Check if stream is already live
	s.mu.Lock()
	if existingStream, exists := s.streams[streamKey]; exists && existingStream.IsLive {
		s.mu.Unlock()
		utils.Logger.Errorf("Stream %s is already live", streamKey)
		return
	}

	// Create new stream status
	now := time.Now()
	streamStatus := &StreamStatus{
		StreamKey:     streamKey,
		IsLive:        true,
		StartTime:     &now,
		ViewerCount:   0,
		ConnectionID:  connID,
		PublisherIP:   strings.Split(nc.RemoteAddr().String(), ":")[0],
		Bitrate:       0,
		Resolution:    "",
		FPS:           0,
		Codec:         "",
		Metadata:      make(map[string]interface{}),
		LastHeartbeat: now,
	}

	s.streams[streamKey] = streamStatus

	// Update connection type
	if connection, exists := s.connections[connID]; exists {
		connection.Type = "publisher"
		connection.StreamKey = streamKey
		connection.StreamID = streamInfo.ID
	}
	s.mu.Unlock()

	// Update database
	if err := s.validator.UpdateStreamStatus(streamKey, true); err != nil {
		utils.Logger.Errorf("Failed to update stream status in database: %v", err)
	}

	utils.Logger.Infof("Stream started: %s (User: %s)", streamKey, streamInfo.UserID)

	// Handle stream data processing
	s.processStreamData(conn, streamKey, streamStatus)
}

// handlePlay handles RTMP play events (viewer connects)
func (s *Server) handlePlay(conn *rtmp.Conn, nc net.Conn, streamKey, connID string) {
	defer func() {
		if r := recover(); r != nil {
			utils.Logger.Errorf("Panic in handlePlay: %v", r)
		}
		s.handleViewerDisconnect(streamKey)
	}()

	utils.Logger.Infof("Play request for stream key: %s", streamKey)

	// Check if stream exists and is live
	s.mu.Lock()
	streamStatus, exists := s.streams[streamKey]
	if !exists || !streamStatus.IsLive {
		s.mu.Unlock()
		utils.Logger.Errorf("Stream %s is not live", streamKey)
		return
	}

	// Increment viewer count
	streamStatus.ViewerCount++
	streamStatus.LastHeartbeat = time.Now()

	// Update connection type
	if connection, exists := s.connections[connID]; exists {
		connection.Type = "subscriber"
		connection.StreamKey = streamKey
	}
	s.mu.Unlock()

	utils.Logger.Infof("Viewer connected to stream: %s (viewers: %d)", streamKey, streamStatus.ViewerCount)

	// Read from the stream until disconnection
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			// Try to read packets - this will block until data is available or connection closes
			_, err := conn.ReadPacket()
			if err != nil {
				utils.Logger.Infof("Viewer disconnected from stream: %s", streamKey)
				return
			}
		}
	}
}
// processStreamData processes incoming stream data and extracts metadata
func (s *Server) processStreamData(conn *rtmp.Conn, streamKey string, streamStatus *StreamStatus) {
	defer func() {
		if r := recover(); r != nil {
			utils.Logger.Errorf("Panic in processStreamData: %v", r)
		}
	}()
	// Process incoming packets
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			pkt, err := conn.ReadPacket()
			if err != nil {
				utils.Logger.Infof("Publisher disconnected from stream: %s", streamKey)
				return
			}

			if err := s.handlePacket(pkt, streamKey, streamStatus); err != nil {
				utils.Logger.Errorf("Error handling packet for stream %s: %v", streamKey, err)
				continue
			}
		}
	}
}
// handlePacket processes individual RTMP packets
func (s *Server) handlePacket(pkt av.Packet, streamKey string, streamStatus *StreamStatus) error {
	// Update heartbeat
	s.mu.Lock()
	streamStatus.LastHeartbeat = time.Now()
	s.mu.Unlock()
	// Process different packet types
	switch pkt.Type {
	case av.H264DecoderConfig, av.H264:
		return s.handleVideoPacket(pkt, streamKey, streamStatus)
	case av.AACDecoderConfig, av.AAC:
		return s.handleAudioPacket(pkt, streamKey, streamStatus)
	case av.Metadata:
		return s.handleMetadataPacket(pkt, streamKey, streamStatus)
	default:
		// Handle other packet types as needed
		return nil
	}
}

// handleVideoPacket processes video packets and extracts video metadata
func (s *Server) handleVideoPacket(pkt av.Packet, streamKey string, streamStatus *StreamStatus) error {
	if len(pkt.Data) < 1 {
		return fmt.Errorf("invalid video packet data")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Determine codec based on packet type
	var codec string
	switch pkt.Type {
	case av.H264DecoderConfig, av.H264:
		codec = "H.264/AVC"
	default:
		codec = "Unknown Video"
	}
	if streamStatus.Codec == "" {
		streamStatus.Codec = codec
		utils.Logger.Infof("Stream %s video codec: %s", streamKey, codec)
	}
	// TODO: Extract resolution, FPS, and bitrate from video data
	// This would require parsing the actual video stream data
	// For H.264, you'd need to parse SPS/PPS data
	return nil
}

// handleAudioPacket processes audio packets
func (s *Server) handleAudioPacket(pkt av.Packet, streamKey string, streamStatus *StreamStatus) error {
	if len(pkt.Data) < 1 {
		return fmt.Errorf("invalid audio packet data")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Determine codec based on packet type
	var audioCodec string
	switch pkt.Type {
	case av.AACDecoderConfig, av.AAC:
		audioCodec = "AAC"
	default:
		audioCodec = "Unknown Audio"
	}
	if streamStatus.Metadata["audio_codec"] == nil {
		streamStatus.Metadata["audio_codec"] = audioCodec
		utils.Logger.Infof("Stream %s audio codec: %s", streamKey, audioCodec)
	}
	return nil
}
// handleMetadataPacket processes metadata packets
func (s *Server) handleMetadataPacket(pkt av.Packet, streamKey string, streamStatus *StreamStatus) error {
	// The joy5 library should handle AMF parsing for metadata
	// You can access metadata through the packet data	
	s.mu.Lock()
	defer s.mu.Unlock()
	// Store raw metadata - you might want to parse this further
	streamStatus.Metadata["last_metadata_size"] = len(pkt.Data)
	streamStatus.Metadata["last_metadata_time"] = time.Now()
	utils.Logger.Debugf("Received metadata packet for stream %s (size: %d)", streamKey, len(pkt.Data))
	return nil
}

func (s *Server) handleStreamEnd(streamKey string) {
	utils.Logger.Infof("Stream ended: %s", streamKey)
	s.mu.Lock()
	streamStatus, exists := s.streams[streamKey]
	if exists {
		streamStatus.IsLive = false
		now := time.Now()
		streamStatus.EndTime = &now
		streamStatus.ViewerCount = 0
	}
	s.mu.Unlock()
	// Update database
	if err := s.validator.UpdateStreamStatus(streamKey, false); err != nil {
		utils.Logger.Errorf("Failed to update stream status in database: %v", err)
	}
}
func (s *Server) handleViewerDisconnect(streamKey string) {
	s.mu.Lock()
	if streamStatus, exists := s.streams[streamKey]; exists {
		streamStatus.ViewerCount--
		if streamStatus.ViewerCount < 0 {
			streamStatus.ViewerCount = 0
		}
		streamStatus.LastHeartbeat = time.Now()
	}
	s.mu.Unlock()
	utils.Logger.Infof("Viewer disconnected from stream: %s", streamKey)
}
func (s *Server) extractStreamKey(streamPath string) string {
	// Extract stream key from path like "/live/stream_key" or "/stream_key"
	parts := strings.Split(strings.TrimPrefix(streamPath, "/"), "/")
	if len(parts) >= 2 {
		return parts[1] // Return the stream key part
	} else if len(parts) == 1 && parts[0] != "" {
		return parts[0] // Direct stream key
	}
	return ""
}
func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()
	// Set connection timeouts
	conn.SetReadDeadline(time.Now().Add(s.config.ReadTimeout))
	conn.SetWriteDeadline(time.Now().Add(s.config.WriteTimeout))
	// Use joy5 to handle RTMP protocol
	s.rtmpSrv.HandleNetConn(conn)
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
func (s *Server) heartbeatMonitor() {
	defer s.wg.Done()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.checkStreamHeartbeats()
		}
	}
}
func (s *Server) checkStreamHeartbeats() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for streamKey, streamStatus := range s.streams {
		if streamStatus.IsLive && now.Sub(streamStatus.LastHeartbeat) > s.config.HeartbeatTimeout {
			utils.Logger.Warnf("Stream heartbeat timeout: %s", streamKey)
			streamStatus.IsLive = false
			endTime := now
			streamStatus.EndTime = &endTime
			streamStatus.ViewerCount = 0
			// Update database
			go func(key string) {
				if err := s.validator.UpdateStreamStatus(key, false); err != nil {
					utils.Logger.Errorf("Failed to update stream status in database: %v", err)
				}
			}(streamKey)
		}
	}
}
func (s *Server) cleanupInactiveConnections() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for id, conn := range s.connections {
		if now.Sub(conn.LastPing) > 5*time.Minute {
			utils.Logger.Infof("Cleaning up inactive connection: %s", id)
			conn.Conn.Close()
			delete(s.connections, id)
		}
	}
}
func (s *Server) cleanupInactiveStreams() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for streamKey, streamStatus := range s.streams {
		if !streamStatus.IsLive && streamStatus.EndTime != nil &&
			now.Sub(*streamStatus.EndTime) > 5*time.Minute {
			utils.Logger.Infof("Cleaning up inactive stream: %s", streamKey)
			delete(s.streams, streamKey)
		}
	}
}
func (s *Server) Stop() error {
	utils.Logger.Info("Stopping RTMP server...")	
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
	// Mark all streams as offline
	for streamKey, streamStatus := range s.streams {
		if streamStatus.IsLive {
			streamStatus.IsLive = false
			now := time.Now()
			streamStatus.EndTime = &now
			streamStatus.ViewerCount = 0

			// Update database
			go func(key string) {
				if err := s.validator.UpdateStreamStatus(key, false); err != nil {
					utils.Logger.Errorf("Failed to update stream status in database: %v", err)
				}
			}(streamKey)
		}
	}
	s.mu.Unlock()
	// Wait for all goroutines to finish
	s.wg.Wait()
	utils.Logger.Info("RTMP server stopped gracefully")
	return nil
}
// GetStats returns comprehensive server statistics
func (s *Server) GetStats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	liveStreams := 0
	totalViewers := 0
	for _, stream := range s.streams {
		if stream.IsLive {
			liveStreams++
			totalViewers += stream.ViewerCount
		}
	}
	uptime := time.Since(s.startTime)
	return map[string]interface{}{
		"server": map[string]interface{}{
			"port":            s.port,
			"connections":     len(s.connections),
			"max_connections": s.config.MaxConnections,
			"uptime":          uptime.String(),
		},
		"streams": map[string]interface{}{
			"total":         len(s.streams),
			"live":          liveStreams,
			"total_viewers": totalViewers,
		},
	}
}
// GetStreamStatus returns the status of a specific stream
func (s *Server) GetStreamStatus(streamKey string) (*StreamStatus, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	status, exists := s.streams[streamKey]
	return status, exists
}
// GetAllStreams returns all stream statuses
func (s *Server) GetAllStreams() map[string]*StreamStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	streams := make(map[string]*StreamStatus)
	for key, status := range s.streams {
		streams[key] = status
	}
	return streams
}
// GetLiveStreams returns only live streams
func (s *Server) GetLiveStreams() map[string]*StreamStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	liveStreams := make(map[string]*StreamStatus)
	for key, status := range s.streams {
		if status.IsLive {
			liveStreams[key] = status
		}
	}
	return liveStreams
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
// UpdateStreamMetadata updates metadata for a stream
func (s *Server) UpdateStreamMetadata(streamKey string, metadata map[string]interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if streamStatus, exists := s.streams[streamKey]; exists {
		if streamStatus.Metadata == nil {
			streamStatus.Metadata = make(map[string]interface{})
		}
		for key, value := range metadata {
			streamStatus.Metadata[key] = value
		}
		streamStatus.LastHeartbeat = time.Now()
		return nil
	}
	return fmt.Errorf("stream not found: %s", streamKey)
}
// ForceEndStream forcefully ends a stream
func (s *Server) ForceEndStream(streamKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	streamStatus, exists := s.streams[streamKey]
	if !exists {
		return fmt.Errorf("stream not found: %s", streamKey)
	}
	if !streamStatus.IsLive {
		return fmt.Errorf("stream is not live: %s", streamKey)
	}
	// Find and close the publisher connection
	var publisherConn *Connection
	for _, conn := range s.connections {
		if conn.StreamKey == streamKey && conn.Type == "publisher" {
			publisherConn = conn
			break
		}
	}
	if publisherConn != nil {
		publisherConn.Conn.Close()
		delete(s.connections, publisherConn.ID)
	}
	// Update stream status
	streamStatus.IsLive = false
	now := time.Now()
	streamStatus.EndTime = &now
	streamStatus.ViewerCount = 0
	// Update database
	go func() {
		if err := s.validator.UpdateStreamStatus(streamKey, false); err != nil {
			utils.Logger.Errorf("Failed to update stream status in database: %v", err)
		}
	}()
	utils.Logger.Infof("Forcefully ended stream: %s", streamKey)
	return nil
}