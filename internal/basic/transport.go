package basic

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type Handler struct {
}

func NewHandler() *Handler {
	return &Handler{}
}

// BasicSecure
// @Summary Secured endpoint
// @Tags basic
// @Security BasicAuth
// @Success 200 {object} map[string]string
// @Router /basic-secure [get]
func (h *Handler) BasicSecure(c *gin.Context) {
	user := c.MustGet(gin.AuthUserKey).(string)
	c.JSON(http.StatusOK, gin.H{"user": user})
}
