package schema

import (
	"database/sql"
	"fmt"
)

func CreateStreamTables(db *sql.DB) error {
	// Create streams table
	query := `
	CREATE TABLE IF NOT EXISTS streams (
		id SERIAL PRIMARY KEY,
		user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
		title VARCHAR(255) NOT NULL,
		description TEXT,
		status VARCHAR(20) DEFAULT 'offline',
		viewer_count INTEGER DEFAULT 0,
		thumbnail_url VARCHAR(255),
		started_at TIMESTAMP WITH TIME ZONE,
		ended_at TIMESTAMP WITH TIME ZONE,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
	);`

	_, err := db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to create streams table: %v", err)
	}

	// Create indexes for streams table
	indexQueries := []string{
		`CREATE INDEX IF NOT EXISTS idx_streams_user_id ON streams(user_id);`,
		`CREATE INDEX IF NOT EXISTS idx_streams_status ON streams(status);`,
		`CREATE INDEX IF NOT EXISTS idx_streams_created_at ON streams(created_at);`,
	}

	for _, query := range indexQueries {
		_, err := db.Exec(query)
		if err != nil {
			return fmt.Errorf("failed to create index: %v", err)
		}
	}

	return nil
}
