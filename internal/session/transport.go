package session

import (
	"all_auth_versions/internal/shared"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type Handler struct {
}

func NewHandler() *Handler {
	return &Handler{}
}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Login
// @Tags session
// @Accept json
// @Produce json
// @Param credentials body Credentials true "Credentials"
// Success 200 {object} map[string]string
// Failure 400 {object} map[string]string
// Failure 401 {object} map[string]string
// @Router /login [post]
func (h *Handler) Login(c *gin.Context) {
	var creds Credentials
	if err := c.BindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}
	// validate username+password
	expectedPassword, ok := shared.UsersDB[creds.Username]
	if !ok || expectedPassword != creds.Password {
		c.AbortWithStatus(http.StatusUnauthorized)
	}

	// if ok then create token
	sessionToken := uuid.NewString()
	expiresAt := time.Now().Add(10 * time.Second)

	sessions[sessionToken] = session{
		username: creds.Username,
		expire:   expiresAt,
	}
	// set cookie
	c.SetCookie("session_token", sessionToken, 60, "", "", false, false)
}

// Secured
// @Tags session
// @Produce json
// Success 200 {object} map[string]string
// Failure 400 {object} map[string]string
// Failure 401 {object} map[string]string
// @Router /home [get]
func (h *Handler) Secured(c *gin.Context) {
	token, err := c.Cookie("session_token")
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}

	// if no logged in (no session stored at server)
	userSession, exists := sessions[token]
	if !exists {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	// if session expired
	if userSession.isExpired() {
		delete(sessions, token)
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// if all ok
	c.JSON(http.StatusOK, gin.H{"message": "hello nigger"})
	return
}

// Refresh
// @Tags session
// @Produce json
// Success 200 {object} map[string]string
// Failure 400 {object} map[string]string
// Failure 401 {object} map[string]string
// @Router /refresh [post]
func (h *Handler) Refresh(c *gin.Context) {
	token, err := c.Cookie("session_token")
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}

	// if no logged in (no session stored at server)
	userSession, exists := sessions[token]
	if !exists {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	// if session expired
	if userSession.isExpired() {
		delete(sessions, token)
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// if all ok
	newToken := uuid.NewString()
	expiresAt := time.Now().Add(10 * time.Second)

	sessions[newToken] = session{
		username: userSession.username,
		expire:   expiresAt,
	}
	delete(sessions, token)
	// set cookie
	c.SetCookie("session_token", newToken, 60, "", "", false, false)
}

// Logout
// @Tags session
// @Produce json
// Success 200 {object} map[string]string
// Failure 400 {object} map[string]string
// Failure 401 {object} map[string]string
// @Router /logout [post]
func (h *Handler) Logout(c *gin.Context) {
	token, err := c.Cookie("session_token")
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}
	delete(sessions, token)
	c.SetCookie("session_token", "", -1, "", "", false, false)
}
