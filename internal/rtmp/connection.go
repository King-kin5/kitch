package rtmp

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	utils "kitch/pkg/utils"

	"github.com/nareix/joy5/format/rtmp"
)

// ConnectionState represents the current state of an RTMP connection
type ConnectionState int

const (
	StateHandshake ConnectionState = iota
	StateConnected
	StateStreaming
	StateDisconnected
)

// ConnectionHandler manages individual RTMP connections
type ConnectionHandler struct {
	conn         *rtmp.Conn
	netConn      net.Conn
	server       *Server
	state        ConnectionState
	mu           sync.RWMutex
	ctx          context.Context
	cancel       context.CancelFunc
	connectionID string
	startTime    time.Time
	lastActivity time.Time
	errorCount   int
	maxErrors    int
}

// NewConnectionHandler creates a new RTMP connection handler
func NewConnectionHandler(conn *rtmp.Conn, netConn net.Conn, server *Server) *ConnectionHandler {
	ctx, cancel := context.WithCancel(context.Background())

	handler := &ConnectionHandler{
		conn:         conn,
		netConn:      netConn,
		server:       server,
		state:        StateHandshake,
		ctx:          ctx,
		cancel:       cancel,
		connectionID: fmt.Sprintf("%s-%d", netConn.RemoteAddr().String(), time.Now().UnixNano()),
		startTime:    time.Now(),
		lastActivity: time.Now(),
		maxErrors:    5,
	}

	return handler
}

// Start begins handling the RTMP connection
func (h *ConnectionHandler) Start() error {
	utils.Logger.Infof("Starting RTMP connection handler: %s", h.connectionID)

	// Set up connection timeouts
	h.netConn.SetReadDeadline(time.Now().Add(h.server.config.ReadTimeout))
	h.netConn.SetWriteDeadline(time.Now().Add(h.server.config.WriteTimeout))

	// Perform RTMP handshake
	if err := h.performHandshake(); err != nil {
		return fmt.Errorf("handshake failed: %w", err)
	}

	// Update state to connected
	h.setState(StateConnected)
	utils.Logger.Infof("RTMP handshake completed for connection: %s", h.connectionID)

	// Start message handling loop
	go h.handleMessages()

	// Start keep-alive routine
	go h.keepAlive()

	return nil
}

// performHandshake implements the RTMP handshake protocol
func (h *ConnectionHandler) performHandshake() error {
	utils.Logger.Debugf("Starting RTMP handshake for connection: %s", h.connectionID)

	// RTMP handshake consists of three phases:
	// 1. C0 + C1 (Client sends version + time + zero + random)
	// 2. S0 + S1 + S2 (Server responds with version + time + time2 + random)
	// 3. C2 (Client sends time + time2 + random)

	// Phase 1: Read C0 + C1
	if err := h.readC0C1(); err != nil {
		return fmt.Errorf("failed to read C0+C1: %w", err)
	}

	// Phase 2: Send S0 + S1 + S2
	if err := h.sendS0S1S2(); err != nil {
		return fmt.Errorf("failed to send S0+S1+S2: %w", err)
	}

	// Phase 3: Read C2
	if err := h.readC2(); err != nil {
		return fmt.Errorf("failed to read C2: %w", err)
	}

	utils.Logger.Debugf("RTMP handshake completed for connection: %s", h.connectionID)
	return nil
}

// readC0C1 reads the client's C0 and C1 messages
func (h *ConnectionHandler) readC0C1() error {
	// Read C0 (1 byte - version)
	c0 := make([]byte, 1)
	if _, err := io.ReadFull(h.netConn, c0); err != nil {
		return fmt.Errorf("failed to read C0: %w", err)
	}

	if c0[0] != 3 {
		return fmt.Errorf("unsupported RTMP version: %d", c0[0])
	}

	// Read C1 (1536 bytes - time + zero + random)
	c1 := make([]byte, 1536)
	if _, err := io.ReadFull(h.netConn, c1); err != nil {
		return fmt.Errorf("failed to read C1: %w", err)
	}

	utils.Logger.Debugf("Read C0+C1 from client: %s", h.connectionID)
	return nil
}

// sendS0S1S2 sends the server's S0, S1, and S2 messages
func (h *ConnectionHandler) sendS0S1S2() error {
	// Send S0 (1 byte - version)
	s0 := []byte{3}
	if _, err := h.netConn.Write(s0); err != nil {
		return fmt.Errorf("failed to send S0: %w", err)
	}

	// Send S1 (1536 bytes - time + zero + random)
	s1 := make([]byte, 1536)
	// Fill with current time and random data
	now := time.Now().Unix()
	copy(s1[0:4], []byte{byte(now >> 24), byte(now >> 16), byte(now >> 8), byte(now)})
	// Fill rest with random data (simplified)
	for i := 4; i < len(s1); i++ {
		s1[i] = byte(i % 256)
	}

	if _, err := h.netConn.Write(s1); err != nil {
		return fmt.Errorf("failed to send S1: %w", err)
	}

	// Send S2 (1536 bytes - time + time2 + random)
	s2 := make([]byte, 1536)
	copy(s2, s1) // Echo back the C1 data

	if _, err := h.netConn.Write(s2); err != nil {
		return fmt.Errorf("failed to send S2: %w", err)
	}

	utils.Logger.Debugf("Sent S0+S1+S2 to client: %s", h.connectionID)
	return nil
}

// readC2 reads the client's C2 message
func (h *ConnectionHandler) readC2() error {
	// Read C2 (1536 bytes - time + time2 + random)
	c2 := make([]byte, 1536)
	if _, err := io.ReadFull(h.netConn, c2); err != nil {
		return fmt.Errorf("failed to read C2: %w", err)
	}

	utils.Logger.Debugf("Read C2 from client: %s", h.connectionID)
	return nil
}

// handleMessages processes RTMP messages using joy5's event handling
func (h *ConnectionHandler) handleMessages() {
	defer h.cleanup()

	// Set up event handlers for joy5
	h.conn.LogStageEvent = func(event string, url string) {
		utils.Logger.Infof("RTMP Stage Event: %s, URL: %s for connection: %s", event, url, h.connectionID)
		h.updateActivity()
	}

	// Handle connection close notification
	go func() {
		<-h.conn.CloseNotify()
		utils.Logger.Infof("RTMP connection closed by client: %s", h.connectionID)
		h.setState(StateDisconnected)
		h.cancel()
	}()

	// Keep the connection alive until context is cancelled
	<-h.ctx.Done()
}

// keepAlive sends periodic keep-alive messages
func (h *ConnectionHandler) keepAlive() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-h.ctx.Done():
			return
		case <-ticker.C:
			if err := h.sendPing(); err != nil {
				utils.Logger.Errorf("Failed to send ping for connection %s: %v", h.connectionID, err)
				h.handleError(err)
				return
			}
		}
	}
}

// sendPing sends a ping message to keep the connection alive
func (h *ConnectionHandler) sendPing() error {
	// Implementation would send the actual RTMP ping message
	utils.Logger.Debugf("Sending ping for connection: %s", h.connectionID)
	return nil
}

// handleError handles connection errors
func (h *ConnectionHandler) handleError(err error) {
	h.errorCount++
	utils.Logger.Errorf("Connection error for %s (error #%d): %v", h.connectionID, h.errorCount, err)

	if h.errorCount >= h.maxErrors {
		utils.Logger.Errorf("Too many errors for connection %s, closing", h.connectionID)
		h.setState(StateDisconnected)
		h.cancel()
	}
}

// updateActivity updates the last activity timestamp
func (h *ConnectionHandler) updateActivity() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lastActivity = time.Now()
}

// setState updates the connection state
func (h *ConnectionHandler) setState(state ConnectionState) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.state = state
	utils.Logger.Debugf("Connection %s state changed to: %d", h.connectionID, state)
}

// getState returns the current connection state
func (h *ConnectionHandler) getState() ConnectionState {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.state
}

// cleanup performs cleanup when the connection is closed
func (h *ConnectionHandler) cleanup() {
	utils.Logger.Infof("Cleaning up connection: %s", h.connectionID)
	h.setState(StateDisconnected)
	h.cancel()

	// Remove from server's connection list
	h.server.mu.Lock()
	delete(h.server.connections, h.connectionID)
	h.server.mu.Unlock()
}

// Stop stops the connection handler
func (h *ConnectionHandler) Stop() {
	utils.Logger.Infof("Stopping connection handler: %s", h.connectionID)
	h.cancel()
}

// GetStats returns connection statistics
func (h *ConnectionHandler) GetStats() map[string]interface{} {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return map[string]interface{}{
		"connection_id": h.connectionID,
		"state":         h.state,
		"start_time":    h.startTime,
		"last_activity": h.lastActivity,
		"error_count":   h.errorCount,
		"remote_addr":   h.netConn.RemoteAddr().String(),
	}
}
