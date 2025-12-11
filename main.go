package main

import (
	_ "all_auth_versions/docs"
	"all_auth_versions/internal/basic"
	"all_auth_versions/internal/session"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// @title All ways to auth
// @version 1.0
// @securityDefinitions.basic BasicAuth
func main() {
	r := gin.Default()

	basicHandler := basic.NewHandler()
	r.GET("/basic-secure", gin.BasicAuth(basic.Accounts), basicHandler.BasicSecure)
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	h := session.NewHandler()
	r.POST("/login", h.Login)
	r.GET("/home", h.Secured)
	r.POST("/refresh", h.Refresh)
	r.POST("/logout", h.Logout)

	r.Run(":8080")
}
