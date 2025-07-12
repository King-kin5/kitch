package Auth
import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
	security "kitch/internal/security"
	"kitch/internal/stream"
	utils "kitch/pkg/utils"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type Handler struct {
	userstore     UserStore
	tokenManager  *security.TokenManager
	emailService  *EmailService
	streamService *stream.StreamService
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code"`
	Details string `json:"details,omitempty"`
}

type SuccessResponse struct {
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}
// NewHandler creates a new authentication handler with all dependencies
func NewHandler(userstore UserStore, config *security.Config, emailService *EmailService, db *sql.DB) *Handler {
	// Initialize stream store and service
	streamStore := stream.NewStreamStore(db)
	streamService := stream.NewStreamService(streamStore)
	return &Handler{
		userstore:     userstore,
		tokenManager:  security.NewTokenManager(config, db),
		emailService:  emailService,
		streamService: streamService,
	}
}
// RegisterUser handles user registration with comprehensive validation and security
func (h *Handler) RegisterUser(c echo.Context) error {
	var input CreateUser
	utils.Logger.Info("Received registration request")
	if err := c.Bind(&input); err != nil {
		utils.Logger.Errorf("Error binding request data: %v", err)
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid request format",
			Code:    "INVALID_REQUEST",
			Details: "Request body could not be parsed",
		})
	}
	input.Username = strings.TrimSpace(input.Username)
	input.Email = strings.TrimSpace(strings.ToLower(input.Email))
	if input.Bio != nil {
		bio := strings.TrimSpace(*input.Bio)
		input.Bio = &bio
	}
	utils.Logger.Infof("Registration attempt for email: %s", maskEmail(input.Email))
	if err := h.validateRegistrationInput(input); err != nil {
		utils.Logger.Warnf("Validation failed: %v", err)
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   err.Error(),
			Code:    "VALIDATION_ERROR",
			Details: "Registration data validation failed",
		})
	}
	// Check database connection
	if err := h.userstore.CheckDBConnection(); err != nil {
		utils.Logger.Errorf("Database connection error: %v", err)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Service temporarily unavailable",
			Code:    "DATABASE_ERROR",
			Details: "Unable to connect to database",
		})
	}
	existingUser, err := h.userstore.GetUserByEmail(input.Email)
	if err != nil {
		utils.Logger.Errorf("Error checking existing email: %v", err)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Registration failed",
			Code:    "DATABASE_ERROR",
			Details: "Failed to verify email uniqueness",
		})
	}
	if existingUser != nil {
		utils.Logger.Infof("Registration attempt with existing email: %s", maskEmail(input.Email))
		return c.JSON(http.StatusConflict, ErrorResponse{
			Error:   "Email address is already registered",
			Code:    "EMAIL_EXISTS",
			Details: "An account with this email already exists",
		})
	}
	existingUsername, err := h.userstore.GetUserByName(input.Username)
	if err != nil {
		utils.Logger.Errorf("Error checking existing username: %v", err)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Registration failed",
			Code:    "DATABASE_ERROR",
			Details: "Failed to verify username uniqueness",
		})
	}
	if existingUsername != nil {
		utils.Logger.Infof("Registration attempt with existing username: %s", input.Username)
		return c.JSON(http.StatusConflict, ErrorResponse{
			Error:   "Username is already taken",
			Code:    "USERNAME_EXISTS",
			Details: "Please choose a different username",
		})
	}
	hashedPassword, err := security.PasswordHash(input.Password)
	if err != nil {
		utils.Logger.Errorf("Error hashing password: %v", err)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Registration failed",
			Code:    "SECURITY_ERROR",
			Details: "Failed to secure password",
		})
	}

	// Begin transaction
	db, ok := h.userstore.(*UserStoreImpl)
	if !ok {
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Registration failed",
			Code:    "DATABASE_ERROR",
			Details: "UserStore is not a UserStoreImpl",
		})
	}
	tx, err := db.db.Begin()
	if err != nil {
		utils.Logger.Errorf("Failed to begin transaction: %v", err)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Registration failed",
			Code:    "DATABASE_ERROR",
			Details: "Failed to begin transaction",
		})
	}
	defer tx.Rollback()
	user := &User{
		ID:         uuid.New(),
		Username:   input.Username,
		Email:      input.Email,
		Password:   hashedPassword,
		Bio:        input.Bio,
		IsActive:   true,
		IsVerified: false,
		LoginCount: 0,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	query := `INSERT INTO users (id, username, email, password_hash, bio, is_active, is_verified, login_count, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`
	_, err = tx.Exec(query, user.ID, user.Username, user.Email, user.Password, user.Bio, user.IsActive, user.IsVerified, user.LoginCount, user.CreatedAt, user.UpdatedAt)
	if err != nil {
		utils.Logger.Errorf("Error creating user: %v", err)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Registration failed",
			Code:    "DATABASE_ERROR",
			Details: "Failed to create user account",
		})
	}
	// Send welcome email synchronously
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := h.emailService.SendWelcomeEmail(ctx, user.Email, user.Username); err != nil {
		utils.Logger.Errorf("Failed to send welcome email to %s: %v", maskEmail(user.Email), err)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Registration failed",
			Code:    "EMAIL_ERROR",
			Details: "Failed to send welcome email",
		})
	}
	// Commit transaction
	if err := tx.Commit(); err != nil {
		utils.Logger.Errorf("Failed to commit transaction: %v", err)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Registration failed",
			Code:    "DATABASE_ERROR",
			Details: "Failed to commit transaction",
		})
	}
	// Generate token pair for automatic login
	tokens, err := h.tokenManager.GenerateTokenPair(user.ID, uuid.New())
	if err != nil {
		utils.Logger.Errorf("Error generating tokens: %v", err)
		// User was created but token generation failed - still return success
		return c.JSON(http.StatusCreated, SuccessResponse{
			Message: "User registered successfully. Please login to continue.",
			Data: map[string]interface{}{
				"user_id":  user.ID,
				"username": user.Username,
				"email":    user.Email,
			},
		})
	}
	cookieConfig := security.GetCookieConfigForContext(c)
	security.SetAuthCookies(c, tokens.AccessToken, tokens.RefreshToken, cookieConfig)
	utils.Logger.Infof("User registration successful for email: %s", maskEmail(input.Email))
	return c.JSON(http.StatusCreated, SuccessResponse{
		Message: "User registered successfully",
		Data: map[string]interface{}{
			"user": user.PrivateUser(),
		},
	})
}
// LoginUser handles user authentication with enhanced security
func (h *Handler) LoginUser(c echo.Context) error {
	var input LoginRequest
	// Bind the request data
	if err := c.Bind(&input); err != nil {
		utils.Logger.Errorf("Error binding login request data: %v", err)
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid request format",
			Code:    "INVALID_REQUEST",
			Details: "Request body could not be parsed",
		})
	}
	// Sanitize input
	input.Email = strings.TrimSpace(strings.ToLower(input.Email))
	utils.Logger.Infof("Login attempt for email: %s", maskEmail(input.Email))
	if input.Email == "" || input.Password == "" {
		utils.Logger.Warn("Login attempt with missing credentials")
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Email and password are required",
			Code:    "MISSING_CREDENTIALS",
			Details: "Both email and password must be provided",
		})
	}
	if !isValidEmail(input.Email) {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid email format",
			Code:    "INVALID_EMAIL",
			Details: "Please provide a valid email address",
		})
	}
	// Get user by email
	user, err := h.userstore.GetUserByEmail(input.Email)
	if err != nil {
		utils.Logger.Errorf("Failed to get user by email: %v", err)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Login failed",
			Code:    "DATABASE_ERROR",
			Details: "Unable to verify user credentials",
		})
	}
	// Check if user exists and password is correct
	if user == nil || !security.CheckPasswordSame(user.Password, input.Password) {
		utils.Logger.Warnf("Invalid login attempt for email: %s", maskEmail(input.Email))
		return c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "Invalid email or password",
			Code:    "INVALID_CREDENTIALS",
			Details: "The email or password you entered is incorrect",
		})
	}
	// Check if user account is active
	if !user.IsActive {
		utils.Logger.Warnf("Login attempt for inactive account: %s", maskEmail(input.Email))
		return c.JSON(http.StatusForbidden, ErrorResponse{
			Error:   "Account is deactivated",
			Code:    "ACCOUNT_INACTIVE",
			Details: "Your account has been deactivated. Please contact support",
		})
	}
	tokens, err := h.tokenManager.GenerateTokenPair(user.ID, uuid.New())
	if err != nil {
		utils.Logger.Errorf("Failed to generate tokens: %v", err)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Login failed",
			Code:    "TOKEN_ERROR",
			Details: "Failed to generate authentication tokens",
		})
	}
	// Update last login time and login count
	now := time.Now()
	user.LastLogin = &now
	user.LoginCount++
	user.UpdatedAt = now
	if err := h.userstore.UpdateUserInfoByID(user.ID.String(), *user); err != nil {
		utils.Logger.Warnf("Failed to update login info for user %s: %v", user.ID, err)
	}
	cookieConfig := security.GetCookieConfigForContext(c)
	security.SetAuthCookies(c, tokens.AccessToken, tokens.RefreshToken, cookieConfig)
	utils.Logger.Infof("User login successful for email: %s", maskEmail(input.Email))
	return c.JSON(http.StatusOK, SuccessResponse{
		Message: "Login successful",
		Data: map[string]interface{}{
			"user":         user.PrivateUser(),
			"access_token": tokens.AccessToken,
		},
	})
}
// UpdateUser updates user information by ID with comprehensive validation
func (h *Handler) UpdateUser(c echo.Context) error {
	var input UpdateUserRequest
	if err := c.Bind(&input); err != nil {
		utils.Logger.Errorf("Error binding update data: %v", err)
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid request format",
			Code:    "INVALID_REQUEST",
			Details: "Request body could not be parsed",
		})
	}
	userID := c.Param("id")
	if userID == "" {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "User ID is required",
			Code:    "MISSING_USER_ID",
			Details: "User ID must be provided in the URL path",
		})
	}
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid user ID format",
			Code:    "INVALID_USER_ID",
			Details: "User ID must be a valid UUID",
		})
	}
	// Fetch the user
	user, err := h.userstore.GetUserByID(userID)
	if err != nil {
		utils.Logger.Errorf("Error fetching user: %v", err)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Failed to fetch user",
			Code:    "DATABASE_ERROR",
			Details: "Unable to retrieve user information",
		})
	}
	if user == nil {
		return c.JSON(http.StatusNotFound, ErrorResponse{
			Error:   "User not found",
			Code:    "USER_NOT_FOUND",
			Details: "No user found with the provided ID",
		})
	}
	// Validate and update fields
	updated := false
	if input.Username != nil {
		newUsername := strings.TrimSpace(*input.Username)
		if newUsername != user.Username {
			if err := h.validateUsername(newUsername); err != nil {
				return c.JSON(http.StatusBadRequest, ErrorResponse{
					Error:   err.Error(),
					Code:    "VALIDATION_ERROR",
					Details: "Username validation failed",
				})
			}
			// Check if new username is available
			existingUser, err := h.userstore.GetUserByName(newUsername)
			if err != nil {
				utils.Logger.Errorf("Error checking username availability: %v", err)
				return c.JSON(http.StatusInternalServerError, ErrorResponse{
					Error:   "Update failed",
					Code:    "DATABASE_ERROR",
					Details: "Failed to verify username availability",
				})
			}
			if existingUser != nil && existingUser.ID != userUUID {
				return c.JSON(http.StatusConflict, ErrorResponse{
					Error:   "Username is already taken",
					Code:    "USERNAME_EXISTS",
					Details: "Please choose a different username",
				})
			}
			user.Username = newUsername
			updated = true
		}
	}
	if input.Bio != nil {
		newBio := strings.TrimSpace(*input.Bio)
		if (user.Bio == nil && newBio != "") || (user.Bio != nil && *user.Bio != newBio) {
			if err := h.validateBio(newBio); err != nil {
				return c.JSON(http.StatusBadRequest, ErrorResponse{
					Error:   err.Error(),
					Code:    "VALIDATION_ERROR",
					Details: "Bio validation failed",
				})
			}
			user.Bio = &newBio
			updated = true
		}
	}
	if input.AvatarURL != nil {
		newAvatarURL := strings.TrimSpace(*input.AvatarURL)
		if (user.AvatarURL == nil && newAvatarURL != "") || (user.AvatarURL != nil && *user.AvatarURL != newAvatarURL) {
			if err := h.validateAvatarURL(newAvatarURL); err != nil {
				return c.JSON(http.StatusBadRequest, ErrorResponse{
					Error:   err.Error(),
					Code:    "VALIDATION_ERROR",
					Details: "Avatar URL validation failed",
				})
			}
			user.AvatarURL = &newAvatarURL
			updated = true
		}
	}
	if !updated {
		return c.JSON(http.StatusOK, SuccessResponse{
			Message: "No changes made",
			Data: map[string]interface{}{
				"user": user.PrivateUser(),
			},
		})
	}
	// Update timestamp
	user.UpdatedAt = time.Now()
	// Save the updated user
	if err := h.userstore.UpdateUserInfoByID(userID, *user); err != nil {
		utils.Logger.Errorf("Error updating user: %v", err)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Failed to update user",
			Code:    "DATABASE_ERROR",
			Details: "Unable to save user changes",
		})
	}
	utils.Logger.Infof("User %s updated successfully", userID)
	return c.JSON(http.StatusOK, SuccessResponse{
		Message: "User updated successfully",
		Data: map[string]interface{}{
			"user": user.PrivateUser(),
		},
	})
}
// Profile retrieves user profile information
func (h *Handler) Profile(c echo.Context) error {
	userID := c.Param("id")
	if userID == "" {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "User ID is required",
			Code:    "MISSING_USER_ID",
			Details: "User ID must be provided in the URL path",
		})
	}
	// Validate UUID format
	if _, err := uuid.Parse(userID); err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid user ID format",
			Code:    "INVALID_USER_ID",
			Details: "User ID must be a valid UUID",
		})
	}

	user, err := h.userstore.GetUserByID(userID)
	if err != nil {
		utils.Logger.Errorf("Error fetching user profile: %v", err)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Failed to fetch user profile",
			Code:    "DATABASE_ERROR",
			Details: "Unable to retrieve user information",
		})
	}
	if user == nil {
		return c.JSON(http.StatusNotFound, ErrorResponse{
			Error:   "User not found",
			Code:    "USER_NOT_FOUND",
			Details: "No user found with the provided ID",
		})
	}
	return c.JSON(http.StatusOK, SuccessResponse{
		Message: "Profile retrieved successfully",
		Data: map[string]interface{}{
			"user": user.PublicUser(),
		},
	})
}

// GetProfileByUsername retrieves user profile by username
func (h *Handler) GetProfileByUsername(c echo.Context) error {
	username := c.Param("username")
	if username == "" {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Username is required",
			Code:    "MISSING_USERNAME",
			Details: "Username must be provided in the URL path",
		})
	}
	user, err := h.userstore.GetUserByName(username)
	if err != nil {
		utils.Logger.Errorf("Error fetching user by username: %v", err)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Failed to fetch user profile",
			Code:    "DATABASE_ERROR",
			Details: "Unable to retrieve user information",
		})
	}
	if user == nil {
		return c.JSON(http.StatusNotFound, ErrorResponse{
			Error:   "User not found",
			Code:    "USER_NOT_FOUND",
			Details: "No user found with the provided username",
		})
	}
	return c.JSON(http.StatusOK, SuccessResponse{
		Message: "Profile retrieved successfully",
		Data: map[string]interface{}{
			"user": user.PublicUser(),
		},
	})
}
// Validation helper methods
func (h *Handler) validateRegistrationInput(input CreateUser) error {
	if input.Username == "" {
		return fmt.Errorf("username is required")
	}
	if input.Email == "" {
		return fmt.Errorf("email is required")
	}
	if input.Password == "" {
		return fmt.Errorf("password is required")
	}
	if err := h.validateUsername(input.Username); err != nil {
		return err
	}
	if err := h.validateEmail(input.Email); err != nil {
		return err
	}
	if err := h.validatePassword(input.Password); err != nil {
		return err
	}
	if input.Bio != nil {
		if err := h.validateBio(*input.Bio); err != nil {
			return err
		}
	}
	return nil
}

func (h *Handler) validateUsername(username string) error {
	if len(username) < 3 {
		return fmt.Errorf("username must be at least 3 characters long")
	}
	if len(username) > 30 {
		return fmt.Errorf("username must be less than 30 characters")
	}
	// Allow alphanumeric, underscores, and hyphens
	validUsername := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	if !validUsername.MatchString(username) {
		return fmt.Errorf("username can only contain letters, numbers, underscores, and hyphens")
	}

	return nil
}

func (h *Handler) validateEmail(email string) error {
	if !isValidEmail(email) {
		return fmt.Errorf("invalid email format")
	}
	return nil
}

func (h *Handler) validatePassword(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}
	if len(password) > 128 {
		return fmt.Errorf("password must be less than 128 characters")
	}

	// Check for at least one uppercase, lowercase, digit, and special character
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	hasDigit := regexp.MustCompile(`\d`).MatchString(password)
	hasSpecial := regexp.MustCompile(`[!@#$%^&*(),.?":{}|<>]`).MatchString(password)

	if !hasUpper || !hasLower || !hasDigit || !hasSpecial {
		return fmt.Errorf("password must contain at least one uppercase letter, lowercase letter, digit, and special character")
	}
	return nil
}

func (h *Handler) validateBio(bio string) error {
	if len(bio) > 500 {
		return fmt.Errorf("bio must be less than 500 characters")
	}
	return nil
}

func (h *Handler) validateAvatarURL(url string) error {
	if url == "" {
		return nil // Empty URL is allowed
	}
	if len(url) > 2048 {
		return fmt.Errorf("avatar URL must be less than 2048 characters")
	}
	// Basic URL validation
	urlRegex := regexp.MustCompile(`^https?://[^\s/$.?#].[^\s]*$`)
	if !urlRegex.MatchString(url) {
		return fmt.Errorf("invalid avatar URL format")
	}
	return nil
}

func maskEmail(email string) string {
	if len(email) == 0 {
		return ""
	}
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return email
	}
	username := parts[0]
	domain := parts[1]
	if len(username) <= 2 {
		return username + "@" + domain
	}
	return username[:2] + "***@" + domain
}
// LogoutUser handles user logout by clearing authentication cookies
func (h *Handler) LogoutUser(c echo.Context) error {
	userID, ok := c.Get("user_id").(uuid.UUID)
	if !ok {
		utils.Logger.Warn("Logout attempt without valid user context")
	} else {
		utils.Logger.Infof("User logout for user ID: %s", userID)
	}
	cookieConfig := security.GetCookieConfigForContext(c)
	security.ClearAuthCookies(c, cookieConfig)
	return c.JSON(http.StatusOK, SuccessResponse{
		Message: "Logout successful",
	})
}
// RefreshToken handles token refresh using the refresh token from cookies
func (h *Handler) RefreshToken(c echo.Context) error {
	// Get refresh token from cookie
	refreshToken := security.GetRefreshTokenFromCookie(c)
	if refreshToken == "" {
		return c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "No refresh token found",
			Code:    "MISSING_REFRESH_TOKEN",
			Details: "Refresh token is required",
		})
	}

	// Validate refresh token
	result, err := h.tokenManager.ValidateToken(refreshToken)
	if err != nil {
		utils.Logger.Errorf("Refresh token validation error: %v", err)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Token validation failed",
			Code:    "TOKEN_VALIDATION_ERROR",
			Details: "Failed to validate refresh token",
		})
	}

	if !result.Valid {
		if result.Expired {
			return c.JSON(http.StatusUnauthorized, ErrorResponse{
				Error:   "Refresh token has expired",
				Code:    "REFRESH_TOKEN_EXPIRED",
				Details: "Please login again",
			})
		}
		return c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "Invalid refresh token",
			Code:    "INVALID_REFRESH_TOKEN",
			Details: "Refresh token is invalid",
		})
	}
	if result.Claims.TokenType != "refresh" {
		return c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "Invalid token type",
			Code:    "INVALID_TOKEN_TYPE",
			Details: "Expected refresh token",
		})
	}
	tokens, err := h.tokenManager.GenerateTokenPair(result.Claims.UserID, result.Claims.SessionID)
	if err != nil {
		utils.Logger.Errorf("Failed to generate new tokens: %v", err)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Token refresh failed",
			Code:    "TOKEN_GENERATION_ERROR",
			Details: "Failed to generate new tokens",
		})
	}
	cookieConfig := security.GetCookieConfigForContext(c)
	security.SetAuthCookies(c, tokens.AccessToken, tokens.RefreshToken, cookieConfig)
	utils.Logger.Infof("Token refreshed successfully for user ID: %s", result.Claims.UserID)
	return c.JSON(http.StatusOK, SuccessResponse{
		Message: "Token refreshed successfully",
	})
}

// Stream Key Management Methods//       
//                             //
//                             //
//                             //
//                             //
//                             //
//                             //
//                             //

// getUserIDFromContext extracts and validates user ID from context
func (h *Handler) getUserIDFromContext(c echo.Context) (uuid.UUID, error) {
	userIDFromContext := c.Get("user_id")
	if userIDFromContext == nil {
		return uuid.Nil, fmt.Errorf("user ID not found in context")
	}
	var parsedUserID uuid.UUID
	switch userID := userIDFromContext.(type) {
	case string:
		var err error
		parsedUserID, err = uuid.Parse(userID)
		if err != nil {
			return uuid.Nil, fmt.Errorf("invalid user ID format")
		}
	case uuid.UUID:
		parsedUserID = userID
	default:
		return uuid.Nil, fmt.Errorf("invalid user ID type in context")
	}
	return parsedUserID, nil
}
// GenerateStreamKey generates a new stream key for the authenticated user
func (h *Handler) GenerateStreamKey(c echo.Context) error {
	// Get user ID from context (set by authentication middleware)
	parsedUserID, err := h.getUserIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "Unauthorized",
			Code:    "UNAUTHORIZED",
			Details: err.Error(),
		})
	}

	var input struct {
		Name string `json:"name"`
	}
	if err := c.Bind(&input); err != nil {
		utils.Logger.Errorf("Error binding stream key request: %v", err)
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid request format",
			Code:    "INVALID_REQUEST",
			Details: "Request body could not be parsed",
		})
	}
	// Validate name
	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" {
		input.Name = "Default Stream Key"
	}
	if len(input.Name) > 100 {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Stream key name too long",
			Code:    "VALIDATION_ERROR",
			Details: "Name must be 100 characters or less",
		})
	}
	// Generate stream key
	streamKey, err := h.streamService.GenerateStreamKey(parsedUserID, input.Name)
	if err != nil {
		utils.Logger.Errorf("Failed to generate stream key for user %s: %v", parsedUserID, err)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Failed to generate stream key",
			Code:    "STREAM_KEY_ERROR",
			Details: "Unable to create stream key",
		})
	}
	utils.Logger.Infof("Generated stream key %s for user %s", streamKey.ID, parsedUserID)
	return c.JSON(http.StatusCreated, SuccessResponse{
		Message: "Stream key generated successfully",
		Data: map[string]interface{}{
			"id":         streamKey.ID,
			"key_value":  streamKey.KeyValue,
			"name":       streamKey.Name,
			"is_active":  streamKey.IsActive,
			"created_at": streamKey.CreatedAt,
		},
	})
}

// GetUserStreamKeys retrieves all stream keys for the authenticated user
func (h *Handler) GetUserStreamKeys(c echo.Context) error {
	// Get user ID from context
	parsedUserID, err := h.getUserIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "Unauthorized",
			Code:    "UNAUTHORIZED",
			Details: err.Error(),
		})
	}

	// Get stream keys
	streamKeys, err := h.streamService.GetStreamKeysByUser(parsedUserID)
	if err != nil {
		utils.Logger.Errorf("Failed to get stream keys for user %s: %v", parsedUserID, err)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Failed to retrieve stream keys",
			Code:    "STREAM_KEY_ERROR",
			Details: "Unable to fetch stream keys",
		})
	}
	// Don't return the actual key values for security
	var safeStreamKeys []map[string]interface{}
	for _, key := range streamKeys {
		safeStreamKeys = append(safeStreamKeys, map[string]interface{}{
			"id":           key.ID,
			"name":         key.Name,
			"is_active":    key.IsActive,
			"last_used_at": key.LastUsedAt,
			"created_at":   key.CreatedAt,
		})
	}
	return c.JSON(http.StatusOK, SuccessResponse{
		Message: "Stream keys retrieved successfully",
		Data:    safeStreamKeys,
	})
}

// GetStreamKey retrieves a specific stream key (without the actual key value)
func (h *Handler) GetStreamKey(c echo.Context) error {
	// Get user ID from context
	parsedUserID, err := h.getUserIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "Unauthorized",
			Code:    "UNAUTHORIZED",
			Details: err.Error(),
		})
	}
	// Get stream key ID from URL parameter
	keyID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid stream key ID",
			Code:    "INVALID_REQUEST",
			Details: "Stream key ID format is invalid",
		})
	}
	// Get stream key
	streamKey, err := h.streamService.GetStreamKeyByID(keyID)
	if err != nil {
		utils.Logger.Errorf("Failed to get stream key %s: %v", keyID, err)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Failed to retrieve stream key",
			Code:    "STREAM_KEY_ERROR",
			Details: "Unable to fetch stream key",
		})
	}

	if streamKey == nil {
		return c.JSON(http.StatusNotFound, ErrorResponse{
			Error:   "Stream key not found",
			Code:    "NOT_FOUND",
			Details: "The requested stream key does not exist",
		})
	}
	// Check if the stream key belongs to the authenticated user
	if streamKey.UserID != parsedUserID {
		return c.JSON(http.StatusForbidden, ErrorResponse{
			Error:   "Access denied",
			Code:    "FORBIDDEN",
			Details: "You don't have permission to access this stream key",
		})
	}
	// Don't return the actual key value for security
	return c.JSON(http.StatusOK, SuccessResponse{
		Message: "Stream key retrieved successfully",
		Data: map[string]interface{}{
			"id":           streamKey.ID,
			"name":         streamKey.Name,
			"is_active":    streamKey.IsActive,
			"last_used_at": streamKey.LastUsedAt,
			"created_at":   streamKey.CreatedAt,
		},
	})
}
// DeactivateStreamKey deactivates a stream key
func (h *Handler) DeactivateStreamKey(c echo.Context) error {
	// Get user ID from context
	parsedUserID, err := h.getUserIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "Unauthorized",
			Code:    "UNAUTHORIZED",
			Details: err.Error(),
		})
	}
	// Get stream key ID from URL parameter
	keyID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid stream key ID",
			Code:    "INVALID_REQUEST",
			Details: "Stream key ID format is invalid",
		})
	}
	// Deactivate stream key
	err = h.streamService.DeactivateStreamKey(keyID, parsedUserID)
	if err != nil {
		utils.Logger.Errorf("Failed to deactivate stream key %s for user %s: %v", keyID, parsedUserID, err)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Failed to deactivate stream key",
			Code:    "STREAM_KEY_ERROR",
			Details: "Unable to deactivate stream key",
		})
	}

	utils.Logger.Infof("Deactivated stream key %s for user %s", keyID, parsedUserID)

	return c.JSON(http.StatusOK, SuccessResponse{
		Message: "Stream key deactivated successfully",
	})
}
// DeleteStreamKey deletes a stream key
func (h *Handler) DeleteStreamKey(c echo.Context) error {
	// Get user ID from context
	parsedUserID, err := h.getUserIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "Unauthorized",
			Code:    "UNAUTHORIZED",
			Details: err.Error(),
		})
	}
	// Get stream key ID from URL parameter
	keyID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid stream key ID",
			Code:    "INVALID_REQUEST",
			Details: "Stream key ID format is invalid",
		})
	}
	// Delete stream key
	err = h.streamService.DeleteStreamKey(keyID, parsedUserID)
	if err != nil {
		utils.Logger.Errorf("Failed to delete stream key %s for user %s: %v", keyID, parsedUserID, err)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Failed to delete stream key",
			Code:    "STREAM_KEY_ERROR",
			Details: "Unable to delete stream key",
		})
	}
	utils.Logger.Infof("Deleted stream key %s for user %s", keyID, parsedUserID)
	return c.JSON(http.StatusOK, SuccessResponse{
		Message: "Stream key deleted successfully",
	})
}
