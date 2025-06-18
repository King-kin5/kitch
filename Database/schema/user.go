package schema

import (
	"database/sql"
	"fmt"
)

// CreateUserTable creates the users table if it doesn't exist
func CreateUserTable(db *sql.DB) error {
	query := `
	CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		username VARCHAR(50) UNIQUE NOT NULL,
		email VARCHAR(255) UNIQUE NOT NULL,
		password_hash VARCHAR(255) NOT NULL,
		stream_key VARCHAR(64) UNIQUE,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		last_login TIMESTAMP WITH TIME ZONE,
		is_active BOOLEAN DEFAULT true,
		is_streamer BOOLEAN DEFAULT false,
		avatar_url VARCHAR(255),
		bio TEXT
	);`

	_, err := db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to create users table: %v", err)
	}

	// Create index on username and email for faster lookups
	indexQueries := []string{
		`CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);`,
		`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);`,
		`CREATE INDEX IF NOT EXISTS idx_users_stream_key ON users(stream_key);`,
	}

	for _, query := range indexQueries {
		_, err := db.Exec(query)
		if err != nil {
			return fmt.Errorf("failed to create index: %v", err)
		}
	}

	return nil
}

// CreateUserSettingsTable creates the user_settings table if it doesn't exist
func CreateUserSettingsTable(db *sql.DB) error {
	query := `
	CREATE TABLE IF NOT EXISTS user_settings (
		user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
		theme VARCHAR(20) DEFAULT 'light',
		notifications_enabled BOOLEAN DEFAULT true,
		email_notifications BOOLEAN DEFAULT true,
		stream_notifications BOOLEAN DEFAULT true,
		chat_enabled BOOLEAN DEFAULT true,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
	);`

	_, err := db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to create user_settings table: %v", err)
	}

	return nil
}

// CreateUserFollowsTable creates the user_follows table if it doesn't exist
func CreateUserFollowsTable(db *sql.DB) error {
	query := `
	CREATE TABLE IF NOT EXISTS user_follows (
		follower_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
		following_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (follower_id, following_id)
	);`

	_, err := db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to create user_follows table: %v", err)
	}

	// Create indexes for faster lookups
	indexQueries := []string{
		`CREATE INDEX IF NOT EXISTS idx_user_follows_follower ON user_follows(follower_id);`,
		`CREATE INDEX IF NOT EXISTS idx_user_follows_following ON user_follows(following_id);`,
	}

	for _, query := range indexQueries {
		_, err := db.Exec(query)
		if err != nil {
			return fmt.Errorf("failed to create index: %v", err)
		}
	}

	return nil
}

// CreateUserSessionsTable creates the user_sessions table if it doesn't exist
func CreateUserSessionsTable(db *sql.DB) error {
	query := `
	CREATE TABLE IF NOT EXISTS user_sessions (
		id SERIAL PRIMARY KEY,
		user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
		token VARCHAR(255) UNIQUE NOT NULL,
		ip_address VARCHAR(45),
		user_agent TEXT,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
		is_active BOOLEAN DEFAULT true
	);`

	_, err := db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to create user_sessions table: %v", err)
	}

	// Create indexes for faster lookups
	indexQueries := []string{
		`CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);`,
		`CREATE INDEX IF NOT EXISTS idx_user_sessions_token ON user_sessions(token);`,
		`CREATE INDEX IF NOT EXISTS idx_user_sessions_expires_at ON user_sessions(expires_at);`,
	}

	for _, query := range indexQueries {
		_, err := db.Exec(query)
		if err != nil {
			return fmt.Errorf("failed to create index: %v", err)
		}
	}

	return nil
}

// CreateAllUserTables creates all user-related tables
func CreateAllUserTables(db *sql.DB) error {
	tables := []func(*sql.DB) error{
		CreateUserTable,
		CreateUserSettingsTable,
		CreateUserFollowsTable,
		CreateUserSessionsTable,
	}

	for _, createTable := range tables {
		if err := createTable(db); err != nil {
			return err
		}
	}

	return nil
}
