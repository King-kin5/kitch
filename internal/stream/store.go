package stream

import (
	"context"
	"database/sql"
	"fmt"
	utils "kitch/pkg/utils"
	"time"

	"github.com/google/uuid"
)

type StreamStoreImpl struct {
	db *sql.DB
}

func NewStreamStore(db *sql.DB) *StreamStoreImpl {
	return &StreamStoreImpl{db: db}
}

// Stream Key Management

func (ss *StreamStoreImpl) CreateStreamKey(streamKey *StreamKey) error {
	tx, err := ss.db.Begin()
	if err != nil {
		utils.Logger.Errorf("Failed to begin transaction: %v", err)
		return fmt.Errorf("database error")
	}
	defer tx.Rollback()

	// Set default values
	now := time.Now()
	streamKey.CreatedAt = now
	streamKey.IsActive = true

	query := `
		INSERT INTO stream_keys (id, user_id, key_value, name, is_active, created_at, updated_at) 
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	_, err = tx.Exec(query,
		streamKey.ID, streamKey.UserID, streamKey.KeyValue, streamKey.Name,
		streamKey.IsActive, streamKey.CreatedAt, streamKey.CreatedAt,
	)
	if err != nil {
		utils.Logger.Errorf("Error creating stream key: %v", err)
		return fmt.Errorf("failed to create stream key")
	}

	return tx.Commit()
}

func (ss *StreamStoreImpl) GetStreamKeyByID(id uuid.UUID) (*StreamKey, error) {
	streamKey := &StreamKey{}
	query := `
		SELECT id, user_id, key_value, name, is_active, last_used_at, created_at, updated_at 
		FROM stream_keys WHERE id = $1
	`

	row := ss.db.QueryRow(query, id)
	err := row.Scan(
		&streamKey.ID, &streamKey.UserID, &streamKey.KeyValue, &streamKey.Name,
		&streamKey.IsActive, &streamKey.LastUsedAt, &streamKey.CreatedAt, &streamKey.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		utils.Logger.Errorf("Error scanning stream key by ID: %v", err)
		return nil, fmt.Errorf("database error")
	}
	return streamKey, nil
}

func (ss *StreamStoreImpl) GetStreamKeyByValue(keyValue string) (*StreamKey, error) {
	streamKey := &StreamKey{}
	query := `
		SELECT id, user_id, key_value, name, is_active, last_used_at, created_at, updated_at 
		FROM stream_keys WHERE key_value = $1 AND is_active = true
	`

	row := ss.db.QueryRow(query, keyValue)
	err := row.Scan(
		&streamKey.ID, &streamKey.UserID, &streamKey.KeyValue, &streamKey.Name,
		&streamKey.IsActive, &streamKey.LastUsedAt, &streamKey.CreatedAt, &streamKey.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		utils.Logger.Errorf("Error scanning stream key by value: %v", err)
		return nil, fmt.Errorf("database error")
	}
	return streamKey, nil
}

func (ss *StreamStoreImpl) GetStreamKeysByUserID(userID uuid.UUID) ([]*StreamKey, error) {
	query := `
		SELECT id, user_id, key_value, name, is_active, last_used_at, created_at, updated_at 
		FROM stream_keys WHERE user_id = $1 ORDER BY created_at DESC
	`

	rows, err := ss.db.Query(query, userID)
	if err != nil {
		utils.Logger.Errorf("Error querying stream keys by user ID: %v", err)
		return nil, fmt.Errorf("database error")
	}
	defer rows.Close()

	var streamKeys []*StreamKey
	for rows.Next() {
		streamKey := &StreamKey{}
		err := rows.Scan(
			&streamKey.ID, &streamKey.UserID, &streamKey.KeyValue, &streamKey.Name,
			&streamKey.IsActive, &streamKey.LastUsedAt, &streamKey.CreatedAt, &streamKey.CreatedAt,
		)
		if err != nil {
			utils.Logger.Errorf("Error scanning stream key: %v", err)
			return nil, fmt.Errorf("database error")
		}
		streamKeys = append(streamKeys, streamKey)
	}

	return streamKeys, nil
}

func (ss *StreamStoreImpl) UpdateStreamKeyLastUsed(id uuid.UUID) error {
	query := `
		UPDATE stream_keys 
		SET last_used_at = $1, updated_at = $1 
		WHERE id = $2
	`

	_, err := ss.db.Exec(query, time.Now(), id)
	if err != nil {
		utils.Logger.Errorf("Error updating stream key last used: %v", err)
		return fmt.Errorf("failed to update stream key")
	}
	return nil
}

func (ss *StreamStoreImpl) DeactivateStreamKey(id uuid.UUID) error {
	query := `
		UPDATE stream_keys 
		SET is_active = false, updated_at = $1 
		WHERE id = $2
	`

	result, err := ss.db.Exec(query, time.Now(), id)
	if err != nil {
		utils.Logger.Errorf("Error deactivating stream key: %v", err)
		return fmt.Errorf("failed to deactivate stream key")
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("stream key not found")
	}

	return nil
}

func (ss *StreamStoreImpl) DeleteStreamKey(id uuid.UUID) error {
	query := `DELETE FROM stream_keys WHERE id = $1`

	result, err := ss.db.Exec(query, id)
	if err != nil {
		utils.Logger.Errorf("Error deleting stream key: %v", err)
		return fmt.Errorf("failed to delete stream key")
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("stream key not found")
	}

	return nil
}

// Stream Management

func (ss *StreamStoreImpl) CreateStream(stream *Stream) error {
	tx, err := ss.db.Begin()
	if err != nil {
		utils.Logger.Errorf("Failed to begin transaction: %v", err)
		return fmt.Errorf("database error")
	}
	defer tx.Rollback()

	// Set default values
	now := time.Now()
	stream.CreatedAt = now
	stream.UpdatedAt = now
	stream.IsLive = false
	stream.ViewerCount = 0

	query := `
		INSERT INTO streams (id, user_id, stream_key_id, title, description, category, 
		                    is_live, viewer_count, created_at, updated_at) 
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`

	_, err = tx.Exec(query,
		stream.ID, stream.UserID, stream.StreamKeyID, stream.Title, stream.Description,
		stream.Category, stream.IsLive, stream.ViewerCount, stream.CreatedAt, stream.UpdatedAt,
	)
	if err != nil {
		utils.Logger.Errorf("Error creating stream: %v", err)
		return fmt.Errorf("failed to create stream")
	}

	return tx.Commit()
}

func (ss *StreamStoreImpl) GetStreamByID(id uuid.UUID) (*Stream, error) {
	stream := &Stream{}
	query := `
		SELECT id, user_id, stream_key_id, title, description, category, is_live, 
		       viewer_count, started_at, ended_at, created_at, updated_at 
		FROM streams WHERE id = $1
	`

	row := ss.db.QueryRow(query, id)
	err := row.Scan(
		&stream.ID, &stream.UserID, &stream.StreamKeyID, &stream.Title, &stream.Description,
		&stream.Category, &stream.IsLive, &stream.ViewerCount, &stream.StartedAt, &stream.EndedAt,
		&stream.CreatedAt, &stream.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		utils.Logger.Errorf("Error scanning stream by ID: %v", err)
		return nil, fmt.Errorf("database error")
	}
	return stream, nil
}

func (ss *StreamStoreImpl) GetStreamsByUserID(userID uuid.UUID) ([]*Stream, error) {
	query := `
		SELECT id, user_id, stream_key_id, title, description, category, is_live, 
		       viewer_count, started_at, ended_at, created_at, updated_at 
		FROM streams WHERE user_id = $1 ORDER BY created_at DESC
	`

	rows, err := ss.db.Query(query, userID)
	if err != nil {
		utils.Logger.Errorf("Error querying streams by user ID: %v", err)
		return nil, fmt.Errorf("database error")
	}
	defer rows.Close()

	var streams []*Stream
	for rows.Next() {
		stream := &Stream{}
		err := rows.Scan(
			&stream.ID, &stream.UserID, &stream.StreamKeyID, &stream.Title, &stream.Description,
			&stream.Category, &stream.IsLive, &stream.ViewerCount, &stream.StartedAt, &stream.EndedAt,
			&stream.CreatedAt, &stream.UpdatedAt,
		)
		if err != nil {
			utils.Logger.Errorf("Error scanning stream: %v", err)
			return nil, fmt.Errorf("database error")
		}
		streams = append(streams, stream)
	}

	return streams, nil
}

func (ss *StreamStoreImpl) GetLiveStreams() ([]*Stream, error) {
	query := `
		SELECT id, user_id, stream_key_id, title, description, category, is_live, 
		       viewer_count, started_at, ended_at, created_at, updated_at 
		FROM streams WHERE is_live = true ORDER BY viewer_count DESC, started_at DESC
	`

	rows, err := ss.db.Query(query)
	if err != nil {
		utils.Logger.Errorf("Error querying live streams: %v", err)
		return nil, fmt.Errorf("database error")
	}
	defer rows.Close()

	var streams []*Stream
	for rows.Next() {
		stream := &Stream{}
		err := rows.Scan(
			&stream.ID, &stream.UserID, &stream.StreamKeyID, &stream.Title, &stream.Description,
			&stream.Category, &stream.IsLive, &stream.ViewerCount, &stream.StartedAt, &stream.EndedAt,
			&stream.CreatedAt, &stream.UpdatedAt,
		)
		if err != nil {
			utils.Logger.Errorf("Error scanning stream: %v", err)
			return nil, fmt.Errorf("database error")
		}
		streams = append(streams, stream)
	}

	return streams, nil
}

func (ss *StreamStoreImpl) StartStream(id uuid.UUID) error {
	query := `
		UPDATE streams 
		SET is_live = true, started_at = $1, updated_at = $1 
		WHERE id = $2
	`

	result, err := ss.db.Exec(query, time.Now(), id)
	if err != nil {
		utils.Logger.Errorf("Error starting stream: %v", err)
		return fmt.Errorf("failed to start stream")
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("stream not found")
	}

	return nil
}

func (ss *StreamStoreImpl) EndStream(id uuid.UUID) error {
	query := `
		UPDATE streams 
		SET is_live = false, ended_at = $1, updated_at = $1 
		WHERE id = $2
	`

	result, err := ss.db.Exec(query, time.Now(), id)
	if err != nil {
		utils.Logger.Errorf("Error ending stream: %v", err)
		return fmt.Errorf("failed to end stream")
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("stream not found")
	}

	return nil
}

func (ss *StreamStoreImpl) UpdateStreamViewerCount(id uuid.UUID, viewerCount int) error {
	query := `
		UPDATE streams 
		SET viewer_count = $1, updated_at = $2 
		WHERE id = $3
	`

	_, err := ss.db.Exec(query, viewerCount, time.Now(), id)
	if err != nil {
		utils.Logger.Errorf("Error updating stream viewer count: %v", err)
		return fmt.Errorf("failed to update stream viewer count")
	}

	return nil
}

func (ss *StreamStoreImpl) UpdateStreamInfo(id uuid.UUID, title, description, category *string) error {
	query := `
		UPDATE streams 
		SET title = COALESCE($1, title), 
		    description = COALESCE($2, description), 
		    category = COALESCE($3, category), 
		    updated_at = $4 
		WHERE id = $5
	`

	result, err := ss.db.Exec(query, title, description, category, time.Now(), id)
	if err != nil {
		utils.Logger.Errorf("Error updating stream info: %v", err)
		return fmt.Errorf("failed to update stream info")
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("stream not found")
	}

	return nil
}

func (ss *StreamStoreImpl) DeleteStream(id uuid.UUID) error {
	query := `DELETE FROM streams WHERE id = $1`

	result, err := ss.db.Exec(query, id)
	if err != nil {
		utils.Logger.Errorf("Error deleting stream: %v", err)
		return fmt.Errorf("failed to delete stream")
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("stream not found")
	}

	return nil
}

// Utility Methods

func (ss *StreamStoreImpl) CheckDBConnection() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := ss.db.PingContext(ctx)
	if err != nil {
		utils.Logger.Errorf("Database connection failed: %v", err)
		return fmt.Errorf("database connection failed")
	}
	return nil
}

func (ss *StreamStoreImpl) GetStreamCount() (int64, error) {
	var count int64
	query := `SELECT COUNT(*) FROM streams`

	err := ss.db.QueryRow(query).Scan(&count)
	if err != nil {
		utils.Logger.Errorf("Error getting stream count: %v", err)
		return 0, fmt.Errorf("database error")
	}

	return count, nil
}

func (ss *StreamStoreImpl) GetLiveStreamCount() (int64, error) {
	var count int64
	query := `SELECT COUNT(*) FROM streams WHERE is_live = true`

	err := ss.db.QueryRow(query).Scan(&count)
	if err != nil {
		utils.Logger.Errorf("Error getting live stream count: %v", err)
		return 0, fmt.Errorf("database error")
	}

	return count, nil
}
