package Auth

import (
	"time"

	"github.com/google/uuid"
)


type User struct {
	ID         uuid.UUID  `json:"id" db:"id"`
	Username   string     `json:"username" db:"username"`
	Email      string     `json:"email" db:"email"`
	Password   string     `json:"-" db:"password_hash"` // Never return password in JSON
	AvatarURL  *string    `json:"avatar_url" db:"avatar_url"`
	Bio        *string    `json:"bio" db:"bio"`
	IsActive   bool       `json:"is_active" db:"is_active"`
	IsVerified bool       `json:"is_verified" db:"is_verified"`
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at" db:"updated_at"`
}

type CreateUserRequest struct {
	Username  string `json:"username" validate:"required,min=3,max=50"`
	Email     string `json:"email" validate:"required,email"`
	Password  string `json:"password" validate:"required,min=8"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type UpdateUserRequest struct {
	Username  *string `json:"username" validate:"omitempty,max=100"`
	Bio       *string `json:"bio" validate:"omitempty,max=500"`
	AvatarURL *string `json:"avatar_url" validate:"omitempty,url"`
}

type LoginResponse struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}
type UserSession struct {
	ID        uuid.UUID `json:"id" db:"id"`
	UserID    uuid.UUID `json:"user_id" db:"user_id"`
	TokenHash string    `json:"-" db:"token_hash"`
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`
	IsActive  bool      `json:"is_active" db:"is_active"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UserAgent *string   `json:"user_agent" db:"user_agent"`
	IPAddress *string   `json:"ip_address" db:"ip_address"`
}