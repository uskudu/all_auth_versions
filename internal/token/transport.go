package token

import (
	"all_auth_versions/internal/shared"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

type Handler struct {
}

func NewHandler() *Handler {
	return &Handler{}
}

// Login
// @Tags token
// @Accept json
// @Produce json
// @Param credentials body shared.Credentials true "Credentials"
// Success 200 {object} map[string]string
// Failure 400 {object} map[string]string
// Failure 401 {object} map[string]string
// @Router /token/login [post]
func (h *Handler) Login(c *gin.Context) {
	var creds shared.Credentials
	if err := c.BindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}
	// validate username+pwd
	expectedPassword, ok := shared.UsersDB[creds.Username]
	if !ok || expectedPassword != creds.Password {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	// create token
	token := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		jwt.MapClaims{
			"sub": creds.Username,
			"exp": time.Now().Add(time.Second * shared.JwtExpSeconds).Unix(),
		})
	// sign token with secret
	tokenSigned, err := token.SignedString([]byte(shared.JwtSecret))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		log.Printf("failed to create jwt token: %v", err)
		return
	}
	// send token
	c.JSON(http.StatusOK, gin.H{"token": tokenSigned})
	return
}

// Secured
// @Tags token
// @Produce json
// Success 200 {object} map[string]string
// Failure 400 {object} map[string]string
// Failure 401 {object} map[string]string
// @Router /token/secure [get]
func (h *Handler) Secured(c *gin.Context) {
	tokenString := c.Request.Header.Get("Authorization")
	log.Printf("token: %v", tokenString)

	// check if token is present
	if len(tokenString) == 0 {
		c.AbortWithStatus(http.StatusUnauthorized)
		log.Println("len == 0")
		return
	}
	fields := strings.Fields(tokenString)
	if len(fields) != 2 && fields[0] != "Bearer" {
		c.AbortWithStatus(http.StatusUnauthorized)
		log.Println("fields < 2 || fields[0] != \"Bearer\"")
		return
	}
	// check if token is valid
	tokenBeared := fields[1]

	// gets disassembled token
	token, err := jwt.Parse(tokenBeared, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signin method: %v", token.Header)
		}
		return []byte(shared.JwtSecret), nil
	})
	if err != nil || token == nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		log.Println("err != nil || token == nil")
		log.Printf("token: %v", token)
		log.Printf("err: %v", err)
		return
	}
	// validates disassembled token
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		c.AbortWithStatus(http.StatusUnauthorized)
		log.Println("claims !ok || !token.Valid")
		return
	}
	// check exp
	exp, ok := claims["exp"].(float64)
	if !ok || float64(time.Now().Unix()) > exp {
		c.AbortWithStatus(http.StatusUnauthorized)
		log.Println("expired")
		return
	}
	// username (sub in token) is correct
	if _, ok = shared.UsersDB[claims["sub"].(string)]; !ok {
		c.AbortWithStatus(http.StatusUnauthorized)
		log.Println("!userExists")
		return
	}
	// finished checking
	c.JSON(http.StatusOK, gin.H{"message": "hello friend"})
	return
}
