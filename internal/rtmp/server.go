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
// NewStreamRelay creates a new stream relay system
func NewStreamRelay(maxViewers, bufferSize int, packetTimeout time.Duration) *StreamRelay {
	return &StreamRelay{
		streams:       make(map[string]*StreamChannel),
		maxViewers:    maxViewers,
		bufferSize:    bufferSize,
		packetTimeout: packetTimeout,
	}
}
// CreateStream creates a new stream channel for a publisher
func (sr *StreamRelay) CreateStream(streamKey string, publisher *rtmp.Conn, publisherConn net.Conn) *StreamChannel {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	// Close existing stream if it exists
	if existing, exists := sr.streams[streamKey]; exists {
		existing.Close()
	}

	stream := &StreamChannel{
		StreamKey:     streamKey,
		Publisher:     publisher,
		PublisherConn: publisherConn,
		Viewers:       make(map[string]*ViewerConnection),
		PacketChan:    make(chan av.Packet, sr.bufferSize),
		MetadataChan:  make(chan av.Packet, 10),
		IsActive:      true,
		StartTime:     time.Now(),
		LastPacket:    time.Now(),
	}

	sr.streams[streamKey] = stream
	
	// Start packet distribution goroutine
	go sr.distributePackets(stream)
	
	utils.Logger.Infof("Created stream relay for: %s", streamKey)
	return stream
}
// AddViewer adds a viewer to a stream
func (sr *StreamRelay) AddViewer(streamKey, viewerID string, viewer *rtmp.Conn, viewerConn net.Conn) error {
	sr.mu.RLock()
	stream, exists := sr.streams[streamKey]
	sr.mu.RUnlock()
	if !exists || !stream.IsActive {
		return fmt.Errorf("stream %s not found or not active", streamKey)
	}
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if len(stream.Viewers) >= sr.maxViewers {
		return fmt.Errorf("viewer limit reached for stream %s", streamKey)
	}
	// FIX: Remove variable name conflict - don't redeclare viewerConn
	viewerConnection := &ViewerConnection{
		ID:         viewerID,
		Conn:       viewer,
		NetConn:    viewerConn, 
		PacketChan: make(chan av.Packet, sr.bufferSize),
		JoinTime:   time.Now(),
		LastPacket: time.Now(),
		IsActive:   true,
	}
	stream.Viewers[viewerID] = viewerConnection
	// Start viewer packet handler
	go sr.handleViewerPackets(stream, viewerConnection)
	// Send recent metadata to new viewer
	go sr.sendMetadataToViewer(stream, viewerConnection)
	utils.Logger.Infof("Added viewer %s to stream %s (total viewers: %d)", viewerID, streamKey, len(stream.Viewers))
	return nil
}
// RemoveViewer removes a viewer from a stream
func (sr *StreamRelay) RemoveViewer(streamKey, viewerID string) {
	sr.mu.RLock()
	stream, exists := sr.streams[streamKey]
	sr.mu.RUnlock()

	if !exists {
		return
	}

	stream.mu.Lock()
	defer stream.mu.Unlock()

	if viewer, exists := stream.Viewers[viewerID]; exists {
		viewer.IsActive = false
		close(viewer.PacketChan)
		delete(stream.Viewers, viewerID)
		utils.Logger.Infof("Removed viewer %s from stream %s (remaining viewers: %d)", viewerID, streamKey, len(stream.Viewers))
	}
}
// RelayPacket relays a packet from publisher to all viewers
func (sr *StreamRelay) RelayPacket(streamKey string, packet av.Packet) error {
	sr.mu.RLock()
	stream, exists := sr.streams[streamKey]
	sr.mu.RUnlock()

	if !exists || !stream.IsActive {
		return fmt.Errorf("stream %s not found or not active", streamKey)
	}

	// Update stream stats
	stream.LastPacket = time.Now()
	stream.PacketCount++

	// Handle metadata packets separately
	if packet.Type == av.Metadata {
		select {
		case stream.MetadataChan <- packet:
		default:
			// Drop metadata if channel is full
		}
	}

	// Relay packet to all viewers
	select {
	case stream.PacketChan <- packet:
		return nil
	default:
		// Drop packet if channel is full
		utils.Logger.Warnf("Dropping packet for stream %s - channel full", streamKey)
		return fmt.Errorf("packet channel full for stream %s", streamKey)
	}
}
// distributePackets distributes packets from the stream channel to all viewers
func (sr *StreamRelay) distributePackets(stream *StreamChannel) {
	defer func() {
		if r := recover(); r != nil {
			utils.Logger.Errorf("Panic in distributePackets for stream %s: %v", stream.StreamKey, r)
		}
	}()
	for packet := range stream.PacketChan {
		if !stream.IsActive {
			break
		}
		stream.mu.RLock()
		viewers := make([]*ViewerConnection, 0, len(stream.Viewers))
		for _, viewer := range stream.Viewers {
			if viewer.IsActive {
				viewers = append(viewers, viewer)
			}
		}
		stream.mu.RUnlock()
		// FIX: Add packet distribution logging for debugging
		if len(viewers) > 0 {
			utils.Logger.Debugf("Distributing packet to %d viewers for stream %s", len(viewers), stream.StreamKey)
		}
		// Distribute packet to all active viewers
		for _, viewer := range viewers {
			select {
			case viewer.PacketChan <- packet:
				viewer.LastPacket = time.Now()
			default:
				// Drop packet for this viewer if channel is full
				utils.Logger.Warnf("Dropping packet for viewer %s - channel full", viewer.ID)
			}
		}
	}
	utils.Logger.Infof("Stopped packet distribution for stream: %s", stream.StreamKey)
}

// handleViewerPackets handles sending packets to a specific viewer
func (sr *StreamRelay) handleViewerPackets(stream *StreamChannel, viewer *ViewerConnection) {
	defer func() {
		if r := recover(); r != nil {
			utils.Logger.Errorf("Panic in handleViewerPackets for viewer %s: %v", viewer.ID, r)
		}
		viewer.IsActive = false
	}()
	utils.Logger.Infof("Started packet handler for viewer: %s", viewer.ID)
	for packet := range viewer.PacketChan {
		if !viewer.IsActive {
			break
		}
		viewer.NetConn.SetWriteDeadline(time.Now().Add(sr.packetTimeout))
		if err := viewer.Conn.WritePacket(packet); err != nil {
			utils.Logger.Errorf("Error sending packet to viewer %s: %v", viewer.ID, err)
			break
		}
		utils.Logger.Debugf("Sent packet to viewer %s (type: %d)", viewer.ID, packet.Type)
	}
	utils.Logger.Infof("Stopped packet handling for viewer: %s", viewer.ID)
}
// sendMetadataToViewer sends recent metadata to a new viewer
func (sr *StreamRelay) sendMetadataToViewer(stream *StreamChannel, viewer *ViewerConnection) {
	// Send any available metadata packets
	for {
		select {
		case metadata := <-stream.MetadataChan:
			if viewer.IsActive {
				viewer.NetConn.SetWriteDeadline(time.Now().Add(sr.packetTimeout))
				if err := viewer.Conn.WritePacket(metadata); err != nil {
					utils.Logger.Errorf("Error sending metadata to viewer %s: %v", viewer.ID, err)
					return
				}
			}
		default:
			return
		}
	}
}
// Close closes a stream channel
func (sc *StreamChannel) Close() {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if !sc.IsActive {
		return
	}
	sc.IsActive = false
	// Close all viewer connections
	for _, viewer := range sc.Viewers {
		viewer.IsActive = false
		if viewer.PacketChan != nil {
			close(viewer.PacketChan)
		}
		if viewer.NetConn != nil {
			viewer.NetConn.Close()
		}
	}
	// Close channels
	if sc.PacketChan != nil {
		close(sc.PacketChan)
	}
	if sc.MetadataChan != nil {
		close(sc.MetadataChan)
	}
	utils.Logger.Infof("Closed stream channel: %s", sc.StreamKey)
}
// GetStreamStats returns statistics for a stream
func (sc *StreamChannel) GetStreamStats() map[string]interface{} {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	return map[string]interface{}{
		"stream_key":    sc.StreamKey,
		"is_active":     sc.IsActive,
		"start_time":    sc.StartTime,
		"last_packet":   sc.LastPacket,
		"packet_count":  sc.PacketCount,
		"viewer_count":  len(sc.Viewers),
		"uptime":        time.Since(sc.StartTime).String(),
	}
}
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
		// Initialize stream relay
		relay: NewStreamRelay(1000, 1000, 5*time.Second),
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

	streamKey := s.extractStreamKey(conn.URL.Path)
	if streamKey == "" {
		utils.Logger.Errorf("No stream key found in URL: %s", conn.URL.Path)
		return
	}
	isPublish := false	
	// Check URL patterns
	if strings.Contains(conn.URL.Path, "/live/") || 
	   strings.Contains(conn.URL.Path, "/publish/") ||
	   strings.Contains(conn.URL.Path, "/stream/") {
		isPublish = true
	}

	s.mu.RLock()
	if streamStatus, exists := s.streams[streamKey]; exists && streamStatus.IsLive {
		isPublish = false // Stream exists, so this is likely a viewer
	} else {
		isPublish = true // No existing stream, so this is likely a publisher
	}
	s.mu.RUnlock()
	utils.Logger.Infof("Connection type determined: %s for stream %s", 
		map[bool]string{true: "publish", false: "play"}[isPublish], streamKey)

	if isPublish {
		s.handlePublish(conn, nc, streamKey, connID)
	} else {
		s.handlePlay(conn, nc, streamKey, connID)
	}
}
// Enhanced handlePublish with relay integration
func (s *Server) handlePublish(conn *rtmp.Conn, nc net.Conn, streamKey, connID string) {
	defer func() {
		if r := recover(); r != nil {
			utils.Logger.Errorf("Panic in handlePublish: %v", r)
		}
		s.handleStreamEnd(streamKey)
		// Clean up relay stream
		s.relay.mu.Lock()
		if stream, exists := s.relay.streams[streamKey]; exists {
			stream.Close()
			delete(s.relay.streams, streamKey)
		}
		s.relay.mu.Unlock()
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
	// Create stream relay
	relayStream := s.relay.CreateStream(streamKey, conn, nc)
	// Update database
	if err := s.validator.UpdateStreamStatus(streamKey, true); err != nil {
		utils.Logger.Errorf("Failed to update stream status in database: %v", err)
	}
	utils.Logger.Infof("Stream started: %s (User: %s)", streamKey, streamInfo.UserID)
	// Handle stream data processing with relay
	s.processStreamData(conn, streamKey, streamStatus, relayStream)
}
// handlePlay handles RTMP play events (viewer connects)
func (s *Server) handlePlay(conn *rtmp.Conn, nc net.Conn, streamKey, connID string) {
	defer func() {
		if r := recover(); r != nil {
			utils.Logger.Errorf("Panic in handlePlay: %v", r)
		}
		s.handleViewerDisconnect(streamKey)
		s.relay.RemoveViewer(streamKey, connID)
	}()
	utils.Logger.Infof("Play request for stream key: %s", streamKey)
	s.mu.Lock()
	streamStatus, exists := s.streams[streamKey]
	if !exists || !streamStatus.IsLive {
		s.mu.Unlock()
		utils.Logger.Errorf("Stream %s is not live", streamKey)
		return
	}
	streamStatus.ViewerCount++
	streamStatus.LastHeartbeat = time.Now()
	if connection, exists := s.connections[connID]; exists {
		connection.Type = "subscriber"
		connection.StreamKey = streamKey
	}
	s.mu.Unlock()
	if err := s.relay.AddViewer(streamKey, connID, conn, nc); err != nil {
		utils.Logger.Errorf("Failed to add viewer to relay: %v", err)
		return
	}
	utils.Logger.Infof("Viewer connected to stream: %s (viewers: %d)", streamKey, streamStatus.ViewerCount)
	<-s.ctx.Done()
}
// processStreamData processes incoming stream data and extracts metadata
func (s *Server) processStreamData(conn *rtmp.Conn, streamKey string, streamStatus *StreamStatus, relayStream *StreamChannel) {
	defer func() {
		if r := recover(); r != nil {
			utils.Logger.Errorf("Panic in processStreamDataWithRelay: %v", r)
		}
	}()
	// Process incoming packets and relay them
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
			// Handle packet for metadata extraction
			if err := s.handlePacket(pkt, streamKey, streamStatus); err != nil {
				utils.Logger.Errorf("Error handling packet for stream %s: %v", streamKey, err)
				continue
			}
			// Relay packet to all viewers
			if err := s.relay.RelayPacket(streamKey, pkt); err != nil {
				utils.Logger.Errorf("Error relaying packet for stream %s: %v", streamKey, err)
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
	// Get relay stats
	s.relay.mu.RLock()
	relayStreams := len(s.relay.streams)
	activeRelayStreams := 0
	for _, stream := range s.relay.streams {
		if stream.IsActive {
			activeRelayStreams++
		}
	}
	s.relay.mu.RUnlock()
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
		"relay": map[string]interface{}{
			"total_streams":  relayStreams,
			"active_streams": activeRelayStreams,
			"max_viewers":    s.relay.maxViewers,
			"buffer_size":    s.relay.bufferSize,
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