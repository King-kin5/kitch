package schema

import (
	"database/sql"
	"fmt"
	utils "kitch/pkg/utils"
	"strings"
)
// CreateStreamKeysTable creates the stream_keys table
func CreateStreamKeysTable(db *sql.DB) error {
	query := `
		CREATE TABLE IF NOT EXISTS stream_keys (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			key_value VARCHAR(255) UNIQUE NOT NULL,
			name VARCHAR(100),
			is_active BOOLEAN DEFAULT true,
			last_used_at TIMESTAMP WITH TIME ZONE,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);

		-- Create indexes for performance
		CREATE INDEX IF NOT EXISTS idx_stream_keys_user_id ON stream_keys(user_id);
		CREATE INDEX IF NOT EXISTS idx_stream_keys_key_value ON stream_keys(key_value);
		CREATE INDEX IF NOT EXISTS idx_stream_keys_is_active ON stream_keys(is_active);
		CREATE INDEX IF NOT EXISTS idx_stream_keys_last_used_at ON stream_keys(last_used_at);
		CREATE INDEX IF NOT EXISTS idx_stream_keys_created_at ON stream_keys(created_at);

		-- Create partial index for active stream keys
		CREATE INDEX IF NOT EXISTS idx_stream_keys_active ON stream_keys(id) WHERE is_active = true;

		-- Add constraints
		ALTER TABLE stream_keys ADD CONSTRAINT chk_key_value_length CHECK (length(key_value) >= 16 AND length(key_value) <= 255);
		ALTER TABLE stream_keys ADD CONSTRAINT chk_name_length CHECK (length(name) <= 100);
		ALTER TABLE stream_keys ADD CONSTRAINT chk_last_used_at_after_created CHECK (last_used_at IS NULL OR last_used_at >= created_at);

		-- Create updated_at trigger
		CREATE TRIGGER update_stream_keys_updated_at 
			BEFORE UPDATE ON stream_keys 
			FOR EACH ROW 
			EXECUTE FUNCTION update_updated_at_column();
	`
	_, err := db.Exec(query)
	if err != nil {
		dbErrStr := err.Error()
		// Ignore errors about existing constraints, indexes, or tables
		if !(strings.Contains(dbErrStr, "already exists") || strings.Contains(dbErrStr, "duplicate key value") || strings.Contains(dbErrStr, "already defined")) {
			utils.Logger.Errorf("Failed to create stream_keys table: %v", err)
			return fmt.Errorf("failed to create stream_keys table: %w", err)
		}
	}
	utils.Logger.Info("Stream keys table created successfully")
	return nil
}
// CreateStreamsTable creates the streams table
func CreateStreamsTable(db *sql.DB) error {
	query := `
		CREATE TABLE IF NOT EXISTS streams (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			stream_key_id UUID NOT NULL REFERENCES stream_keys(id) ON DELETE CASCADE,
			title VARCHAR(200) NOT NULL,
			description TEXT,
			category VARCHAR(100),
			is_live BOOLEAN DEFAULT false,
			viewer_count INTEGER DEFAULT 0,
			started_at TIMESTAMP WITH TIME ZONE,
			ended_at TIMESTAMP WITH TIME ZONE, 
			thumbnail_url VARCHAR(2048),
			rtmp_url VARCHAR(2048),
			hls_url VARCHAR(2048),
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);

		-- Create indexes for performance
		CREATE INDEX IF NOT EXISTS idx_streams_user_id ON streams(user_id);
		CREATE INDEX IF NOT EXISTS idx_streams_stream_key_id ON streams(stream_key_id);
		CREATE INDEX IF NOT EXISTS idx_streams_is_live ON streams(is_live);
		CREATE INDEX IF NOT EXISTS idx_streams_category ON streams(category);
		CREATE INDEX IF NOT EXISTS idx_streams_started_at ON streams(started_at);
		CREATE INDEX IF NOT EXISTS idx_streams_created_at ON streams(created_at);
		CREATE INDEX IF NOT EXISTS idx_streams_viewer_count ON streams(viewer_count);

		-- Create partial index for live streams
		CREATE INDEX IF NOT EXISTS idx_streams_live ON streams(id) WHERE is_live = true;

		-- Create composite index for user's streams
		CREATE INDEX IF NOT EXISTS idx_streams_user_created ON streams(user_id, created_at DESC);

		-- Add constraints
		ALTER TABLE streams ADD CONSTRAINT chk_title_length CHECK (length(title) >= 1 AND length(title) <= 200);
		ALTER TABLE streams ADD CONSTRAINT chk_description_length CHECK (length(description) <= 2000);
		ALTER TABLE streams ADD CONSTRAINT chk_category_length CHECK (length(category) <= 100);
		ALTER TABLE streams ADD CONSTRAINT chk_viewer_count CHECK (viewer_count >= 0);
		ALTER TABLE streams ADD CONSTRAINT chk_ended_at_after_started CHECK (ended_at IS NULL OR started_at IS NULL OR ended_at >= started_at);
		ALTER TABLE streams ADD CONSTRAINT chk_thumbnail_url_length CHECK (length(thumbnail_url) <= 2048);
		ALTER TABLE streams ADD CONSTRAINT chk_rtmp_url_length CHECK (length(rtmp_url) <= 2048);
		ALTER TABLE streams ADD CONSTRAINT chk_hls_url_length CHECK (length(hls_url) <= 2048);

		-- Create updated_at trigger
		CREATE TRIGGER update_streams_updated_at 
			BEFORE UPDATE ON streams 
			FOR EACH ROW 
			EXECUTE FUNCTION update_updated_at_column();
	`

	_, err := db.Exec(query)
	if err != nil {
		dbErrStr := err.Error()
		// Ignore errors about existing constraints, indexes, or tables
		if !(strings.Contains(dbErrStr, "already exists") || strings.Contains(dbErrStr, "duplicate key value") || strings.Contains(dbErrStr, "already defined")) {
			utils.Logger.Errorf("Failed to create streams table: %v", err)
			return fmt.Errorf("failed to create streams table: %w", err)
		}
	}

	utils.Logger.Info("Streams table created successfully")
	return nil
}

// CreateStreamViewersTable creates the stream_viewers table for tracking viewer sessions
func CreateStreamViewersTable(db *sql.DB) error {
	query := `
		CREATE TABLE IF NOT EXISTS stream_viewers (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			stream_id UUID NOT NULL REFERENCES streams(id) ON DELETE CASCADE,
			user_id UUID REFERENCES users(id) ON DELETE SET NULL,
			session_id VARCHAR(255) NOT NULL,
			ip_address INET,
			user_agent TEXT,
			joined_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			left_at TIMESTAMP WITH TIME ZONE,
			watch_duration INTEGER DEFAULT 0, -- in seconds
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);

		-- Create indexes for performance
		CREATE INDEX IF NOT EXISTS idx_stream_viewers_stream_id ON stream_viewers(stream_id);
		CREATE INDEX IF NOT EXISTS idx_stream_viewers_user_id ON stream_viewers(user_id);
		CREATE INDEX IF NOT EXISTS idx_stream_viewers_session_id ON stream_viewers(session_id);
		CREATE INDEX IF NOT EXISTS idx_stream_viewers_joined_at ON stream_viewers(joined_at);
		CREATE INDEX IF NOT EXISTS idx_stream_viewers_left_at ON stream_viewers(left_at);

		-- Create partial index for active viewers (not left yet)
		CREATE INDEX IF NOT EXISTS idx_stream_viewers_active ON stream_viewers(id) WHERE left_at IS NULL;

		-- Add constraints
		ALTER TABLE stream_viewers ADD CONSTRAINT chk_session_id_length CHECK (length(session_id) >= 16);
		ALTER TABLE stream_viewers ADD CONSTRAINT chk_watch_duration CHECK (watch_duration >= 0);
		ALTER TABLE stream_viewers ADD CONSTRAINT chk_left_at_after_joined CHECK (left_at IS NULL OR left_at >= joined_at);
	`

	_, err := db.Exec(query)
	if err != nil {
		dbErrStr := err.Error()
		// Ignore errors about existing constraints, indexes, or tables
		if !(strings.Contains(dbErrStr, "already exists") || strings.Contains(dbErrStr, "duplicate key value") || strings.Contains(dbErrStr, "already defined")) {
			utils.Logger.Errorf("Failed to create stream_viewers table: %v", err)
			return fmt.Errorf("failed to create stream_viewers table: %w", err)
		}
	}

	utils.Logger.Info("Stream viewers table created successfully")
	return nil
}

// CreateStreamChatTable creates the stream_chat table for chat messages
func CreateStreamChatTable(db *sql.DB) error {
	query := `
		CREATE TABLE IF NOT EXISTS stream_chat (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			stream_id UUID NOT NULL REFERENCES streams(id) ON DELETE CASCADE,
			user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			message TEXT NOT NULL,
			is_deleted BOOLEAN DEFAULT false,
			deleted_at TIMESTAMP WITH TIME ZONE,
			deleted_by UUID REFERENCES users(id) ON DELETE SET NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);

		-- Create indexes for performance
		CREATE INDEX IF NOT EXISTS idx_stream_chat_stream_id ON stream_chat(stream_id);
		CREATE INDEX IF NOT EXISTS idx_stream_chat_user_id ON stream_chat(user_id);
		CREATE INDEX IF NOT EXISTS idx_stream_chat_created_at ON stream_chat(created_at);
		CREATE INDEX IF NOT EXISTS idx_stream_chat_is_deleted ON stream_chat(is_deleted);

		-- Create composite index for stream chat messages
		CREATE INDEX IF NOT EXISTS idx_stream_chat_stream_created ON stream_chat(stream_id, created_at DESC);

		-- Create partial index for non-deleted messages
		CREATE INDEX IF NOT EXISTS idx_stream_chat_active ON stream_chat(id) WHERE is_deleted = false;

		-- Add constraints
		ALTER TABLE stream_chat ADD CONSTRAINT chk_message_length CHECK (length(message) >= 1 AND length(message) <= 500);
		ALTER TABLE stream_chat ADD CONSTRAINT chk_deleted_at_after_created CHECK (deleted_at IS NULL OR deleted_at >= created_at);
	`

	_, err := db.Exec(query)
	if err != nil {
		dbErrStr := err.Error()
		// Ignore errors about existing constraints, indexes, or tables
		if !(strings.Contains(dbErrStr, "already exists") || strings.Contains(dbErrStr, "duplicate key value") || strings.Contains(dbErrStr, "already defined")) {
			utils.Logger.Errorf("Failed to create stream_chat table: %v", err)
			return fmt.Errorf("failed to create stream_chat table: %w", err)
		}
	}

	utils.Logger.Info("Stream chat table created successfully")
	return nil
}

// CreateAllStreamingTables creates all streaming-related tables
func CreateAllStreamingTables(db *sql.DB) error {
	tables := []struct {
		name string
		fn   func(*sql.DB) error
	}{
		{"stream_keys", CreateStreamKeysTable},
		{"streams", CreateStreamsTable},
		{"stream_viewers", CreateStreamViewersTable},
		{"stream_chat", CreateStreamChatTable},
	}

	for _, table := range tables {
		utils.Logger.Infof("Creating %s table...", table.name)
		if err := table.fn(db); err != nil {
			return fmt.Errorf("failed to create %s table: %w", table.name, err)
		}
	}

	utils.Logger.Info("All streaming tables created successfully")
	return nil
}

// CreateStreamingFunctions creates database functions for streaming operations
func CreateStreamingFunctions(db *sql.DB) error {
	query := `
		-- Function to get stream statistics
		CREATE OR REPLACE FUNCTION get_stream_statistics()
		RETURNS TABLE(
			total_streams BIGINT,
			live_streams BIGINT,
			total_viewers BIGINT,
			streams_this_month BIGINT,
			streams_this_week BIGINT
		) AS $$
		BEGIN
			RETURN QUERY
			SELECT 
				COUNT(*) as total_streams,
				COUNT(*) FILTER (WHERE is_live = true) as live_streams,
				COALESCE(SUM(viewer_count), 0) as total_viewers,
				COUNT(*) FILTER (WHERE created_at >= date_trunc('month', NOW())) as streams_this_month,
				COUNT(*) FILTER (WHERE created_at >= date_trunc('week', NOW())) as streams_this_week
			FROM streams;
		END;
		$$ LANGUAGE plpgsql;

		-- Function to cleanup old stream data
		CREATE OR REPLACE FUNCTION cleanup_old_stream_data()
		RETURNS INTEGER AS $$
		DECLARE
			deleted_count INTEGER;
		BEGIN
			-- Clean up old stream viewers (keep last 30 days)
			DELETE FROM stream_viewers WHERE joined_at < NOW() - INTERVAL '30 days';
			GET DIAGNOSTICS deleted_count = ROW_COUNT;
			
			-- Clean up old chat messages (keep last 90 days)
			DELETE FROM stream_chat WHERE created_at < NOW() - INTERVAL '90 days';
			
			RETURN deleted_count;
		END;
		$$ LANGUAGE plpgsql;

		-- Function to get user's stream keys
		CREATE OR REPLACE FUNCTION get_user_stream_keys(user_uuid UUID)
		RETURNS TABLE(
			id UUID,
			key_value VARCHAR(255),
			name VARCHAR(100),
			is_active BOOLEAN,
			last_used_at TIMESTAMP WITH TIME ZONE,
			created_at TIMESTAMP WITH TIME ZONE
		) AS $$
		BEGIN
			RETURN QUERY
			SELECT 
				sk.id,
				sk.key_value,
				sk.name,
				sk.is_active,
				sk.last_used_at,
				sk.created_at
			FROM stream_keys sk
			WHERE sk.user_id = user_uuid
			ORDER BY sk.created_at DESC;
		END;
		$$ LANGUAGE plpgsql;

		-- Function to get user's streams
		CREATE OR REPLACE FUNCTION get_user_streams(user_uuid UUID)
		RETURNS TABLE(
			id UUID,
			title VARCHAR(200),
			description TEXT,
			category VARCHAR(100),
			is_live BOOLEAN,
			viewer_count INTEGER,
			started_at TIMESTAMP WITH TIME ZONE,
			ended_at TIMESTAMP WITH TIME ZONE,
			created_at TIMESTAMP WITH TIME ZONE
		) AS $$
		BEGIN
			RETURN QUERY
			SELECT 
				s.id,
				s.title,
				s.description,
				s.category,
				s.is_live,
				s.viewer_count,
				s.started_at,
				s.ended_at,
				s.created_at
			FROM streams s
			WHERE s.user_id = user_uuid
			ORDER BY s.created_at DESC;
		END;
		$$ LANGUAGE plpgsql;
	`

	_, err := db.Exec(query)
	if err != nil {
		utils.Logger.Errorf("Failed to create streaming functions: %v", err)
		return fmt.Errorf("failed to create streaming functions: %w", err)
	}

	utils.Logger.Info("Streaming functions created successfully")
	return nil
} 