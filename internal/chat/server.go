package chat

import (
	"encoding/json"
	"math/rand"
	"sync"
	"time"

	utils "kitch/pkg/utils"

	"github.com/gorilla/websocket"
)

type Server struct {
	clients    map[string]*Client
	rooms      map[string]*Room
	broadcast  chan *Message
	register   chan *Client
	unregister chan *Client
	mu         sync.RWMutex
}

type Client struct {
	ID       string
	UserID   string
	Username string
	Conn     *websocket.Conn
	Server   *Server
	Room     *Room
	Send     chan []byte
}

type Room struct {
	ID        string
	Name      string
	StreamID  string
	Clients   map[string]*Client
	Messages  []*Message
	CreatedAt time.Time
	mu        sync.RWMutex
}

type Message struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Content   string    `json:"content"`
	UserID    string    `json:"userId"`
	Username  string    `json:"username"`
	RoomID    string    `json:"roomId"`
	CreatedAt time.Time `json:"createdAt"`
}

func NewServer() *Server {
	return &Server{
		clients:    make(map[string]*Client),
		rooms:      make(map[string]*Room),
		broadcast:  make(chan *Message),
		register:   make(chan *Client),
		unregister: make(chan *Client),
	}
}

func (s *Server) Start() {
	for {
		select {
		case client := <-s.register:
			s.mu.Lock()
			s.clients[client.ID] = client
			s.mu.Unlock()

		case client := <-s.unregister:
			s.mu.Lock()
			if _, ok := s.clients[client.ID]; ok {
				delete(s.clients, client.ID)
				close(client.Send)
			}
			s.mu.Unlock()

		case message := <-s.broadcast:
			s.mu.RLock()
			room, ok := s.rooms[message.RoomID]
			s.mu.RUnlock()

			if ok {
				room.mu.Lock()
				room.Messages = append(room.Messages, message)
				for _, client := range room.Clients {
					select {
					case client.Send <- messageToBytes(message):
					default:
						close(client.Send)
						delete(room.Clients, client.ID)
					}
				}
				room.mu.Unlock()
			}
		}
	}
}

func (s *Server) CreateRoom(streamID string) *Room {
	room := &Room{
		ID:        streamID,
		Name:      "Stream Chat",
		StreamID:  streamID,
		Clients:   make(map[string]*Client),
		Messages:  make([]*Message, 0),
		CreatedAt: time.Now(),
	}

	s.mu.Lock()
	s.rooms[streamID] = room
	s.mu.Unlock()

	return room
}

func (s *Server) GetRoom(streamID string) (*Room, bool) {
	s.mu.RLock()
	room, ok := s.rooms[streamID]
	s.mu.RUnlock()
	return room, ok
}

func (c *Client) ReadPump() {
	defer func() {
		c.Server.unregister <- c
		c.Conn.Close()
	}()

	for {
		_, message, err := c.Conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				utils.Logger.Errorf("WebSocket read error: %v", err)
			}
			break
		}

		var msg Message
		if err := json.Unmarshal(message, &msg); err != nil {
			utils.Logger.Errorf("Error unmarshaling message: %v", err)
			continue
		}

		msg.ID = generateMessageID()
		msg.UserID = c.UserID
		msg.Username = c.Username
		msg.CreatedAt = time.Now()

		c.Server.broadcast <- &msg
	}
}

func (c *Client) WritePump() {
	defer func() {
		c.Conn.Close()
	}()

	for {
		message, ok := <-c.Send
		if !ok {
			c.Conn.WriteMessage(websocket.CloseMessage, []byte{})
			return
		}

		w, err := c.Conn.NextWriter(websocket.TextMessage)
		if err != nil {
			return
		}
		w.Write(message)

		if err := w.Close(); err != nil {
			return
		}
	}
}

func messageToBytes(msg *Message) []byte {
	data, err := json.Marshal(msg)
	if err != nil {
		utils.Logger.Errorf("Error marshaling message: %v", err)
		return nil
	}
	return data
}

func generateMessageID() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 6)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return time.Now().Format("20060102150405") + string(b)
}
