# Kitch - Go Live Streaming Platform

A modern live streaming platform built with Go, featuring RTMP ingestion, HLS distribution, and real-time features.

## Project Overview

Kitch is a comprehensive live streaming solution that handles everything from stream ingestion to playback, including user authentication, chat, and stream management.

### Architecture Flow
```
User Auth → RTMP Ingestion → FFmpeg Processing → HLS Distribution → Web Player
```

## Project Structure
```
kitch/
├── cmd/                    # Application entry points
│   └── server/            # Main server application
│       └── main.go        # Application entry point
│
├── internal/              # Private application code
│   ├── auth/             # Authentication service
│   │   ├── model/        # User models and database schemas
│   │   ├── service/      # Authentication business logic
│   │   └── security/     # Security utilities (JWT, hashing)
│   │
│   ├── rtmp/             # RTMP server implementation
│   │   └── server.go     # RTMP server and connection handling
│   │
│   ├── stream/           # Stream processing and management
│   │   └── processor.go  # Stream processing orchestrator
│   │
│   ├── chat/             # Real-time chat system
│   │   └── server.go     # WebSocket chat server
│   │
│   └── api/              # HTTP API handlers
│       ├── handlers/     # Request handlers
│       └── middleware/   # HTTP middleware
│
├── pkg/                   # Public libraries
│   ├── ffmpeg/           # FFmpeg wrapper
│   │   └── ffmpeg.go     # Video processing interface
│   │
│   ├── hls/              # HLS generation and management
│   │   └── manager.go    # Playlist and segment management
│   │
│   └── utils/            # Common utilities
│       ├── errors.go     # Error handling utilities
│       └── logger.go     # Logging utilities
│
├── web/                   # Frontend application
│   ├── src/              # React source code
│   └── public/           # Static assets
│
├── configs/              # Configuration files
│   └── config.go        # Application configuration
│
├── scripts/              # Build and deployment scripts
│
├── docker/               # Docker configuration files
│   └── Dockerfile.dev   # Development Dockerfile
│
├── Database/            # Database related files
│   └── migrations/      # Database migrations
│
├── docker-compose.yml   # Docker Compose configuration
├── .air.toml           # Hot reload configuration
└── README.md           # Project documentation
```

### Component Descriptions

#### Authentication (`internal/auth/`)
- User registration and login
- JWT token management
- Password hashing and security
- User profile management

#### RTMP Server (`internal/rtmp/`)
- RTMP protocol implementation
- Stream ingestion handling
- Stream key validation
- Connection management

#### Stream Processing (`internal/stream/`)
- Video transcoding orchestration
- Quality level management
- Stream health monitoring
- Resource management

#### Chat System (`internal/chat/`)
- WebSocket-based real-time chat
- Room-based chat management
- Message persistence
- User presence tracking

#### FFmpeg Wrapper (`pkg/ffmpeg/`)
- Video transcoding interface
- Stream information extraction
- Thumbnail generation
- Process monitoring

#### HLS Manager (`pkg/hls/`)
- HLS playlist generation
- Segment management
- Stream directory structure
- Cleanup routines

## Development Setup

### Prerequisites
- Go 1.21+
- Docker and Docker Compose
- Node.js 18+ (for frontend)
- FFmpeg

### Environment Setup
1. Clone the repository
2. Copy `.env.example` to `.env` and configure variables
3. Run `docker-compose up -d` for development services
4. Run `go mod download` to install dependencies
5. Run `make dev` to start the development server

## Project Roadmap

### Phase 1: Core Infrastructure (Weeks 1-3)

#### Step 1: Project Setup & Basic Infrastructure
- [x] Initialize Go modules and project structure
- [x] Set up Docker containers for development (PostgreSQL, Redis)
- [x] Create basic database schema (users, streams, stream_keys)
- [x] Set up environment configuration management
- [x] Create basic logging and error handling utilities

#### Step 2: User Authentication Service
- [x] User registration/login endpoints
- [x] JWT token generation and validation
- [x] Password hashing and security
- [] Basic user profile management
- [] Stream key generation for users

#### Step 3: Basic RTMP Ingestion Server
- [] RTMP server that accepts incoming streams
- [] Stream key validation against database
- [] Basic connection handling and logging
- [] Stream status tracking (live/offline)
- [] Simple stream metadata storage

### Phase 2: Video Processing Pipeline (Weeks 4-6)

#### Step 4: FFmpeg Integration
- [] Go wrapper for FFmpeg command execution
- [] Basic transcoding to single quality (720p)
- [] HLS segment generation
- [] File storage management (local first)
- [] Process monitoring and error handling

#### Step 5: Stream Processing Orchestrator
- [] Queue system for processing jobs
- [] Worker pool management for FFmpeg processes
- [] Stream health monitoring
- [] Automatic restart on failures
- [] Resource usage tracking

#### Step 6: Basic HLS Distribution
- [] HTTP server to serve HLS playlists and segments
- [] CORS handling for web players
- [] Basic caching headers
- [] Playlist generation and management
- [] Segment cleanup routines

### Phase 3: Frontend & Playback (Weeks 7-9)

#### Step 7: Basic Web Interface
- [ ] Simple React app with routing
- [ ] User registration/login forms
- [ ] Stream dashboard for streamers
- [ ] Basic stream browsing page
- [ ] User authentication state management

#### Step 8: Video Player Integration
- [ ] HLS.js integration for video playback
- [ ] Basic player controls
- [ ] Stream discovery and selection
- [ ] Player error handling
- [ ] Mobile-responsive player

#### Step 9: Streaming Dashboard
- [ ] Stream key display for users
- [ ] Stream status monitoring
- [ ] Basic analytics (viewer count)
- [ ] Stream start/stop controls
- [ ] Stream settings management

### Phase 4: Real-time Features (Weeks 10-12)

#### Step 10: Chat System
- [] WebSocket server for real-time chat
- [] Chat message storage and retrieval
- [] User presence management
- [] Basic moderation (ban/timeout)
- [] Chat history and persistence

#### Step 11: Real-time Stream Updates
- [ ] Live viewer count updates
- [ ] Stream status notifications
- [ ] Follow/notification system
- [ ] Real-time stream discovery updates
- [ ] WebSocket connection management

#### Step 12: Enhanced Stream Management
- [ ] Stream categories and tags
- [ ] Title and description updates
- [ ] Thumbnail generation and management
- [ ] Stream scheduling
- [ ] Basic search functionality

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. 