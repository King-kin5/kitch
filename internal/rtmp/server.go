package rtmp

import (
	"log"
	"net"
)

type Server struct {
	port     int
	listener net.Listener
	streams  map[string]*Stream
}

type Stream struct {
	ID       string
	Key      string
	IsLive   bool
	Viewers  int
	Metadata map[string]interface{}
}

func NewServer(port int) *Server {
	return &Server{
		port:    port,
		streams: make(map[string]*Stream),
	}
}

func (s *Server) Start() error {
	listener, err := net.Listen("tcp", ":"+string(s.port))
	if err != nil {
		return err
	}
	s.listener = listener

	log.Printf("RTMP server listening on port %d", s.port)

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}

		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()
	// TODO: Implement RTMP protocol handling
	// 1. Handshake
	// 2. Connect
	// 3. CreateStream
	// 4. Play/Publish
}

func (s *Server) Stop() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}
