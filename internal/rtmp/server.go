package rtmp

import (
	"net"
	"strconv"

	utils "kitch/pkg/utils"
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
	listener, err := net.Listen("tcp", ":"+strconv.Itoa(s.port))
	if err != nil {
		return err
	}
	s.listener = listener

	utils.Logger.Infof("RTMP server listening on port %d", s.port)

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			utils.Logger.Errorf("Error accepting connection: %v", err)
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
