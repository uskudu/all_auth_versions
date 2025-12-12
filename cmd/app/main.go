package main

import (
	_ "all_auth_versions/docs"
	"all_auth_versions/internal/basic"
	"all_auth_versions/internal/session"
	"all_auth_versions/internal/shared"
	"all_auth_versions/internal/token"

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
	sessionHandler := session.NewHandler()
	tokenHandler := token.NewHandler()

	basicGroup := r.Group("/basic")
	sessionGroup := r.Group("/session")
	tokenGroup := r.Group("/token")

	basicGroup.GET("/secure", gin.BasicAuth(shared.UsersDB), basicHandler.BasicSecure)

	sessionGroup.POST("/login", sessionHandler.Login)
	sessionGroup.GET("/secure", sessionHandler.Secured)
	sessionGroup.POST("/refresh", sessionHandler.Refresh)
	sessionGroup.POST("/logout", sessionHandler.Logout)

	tokenGroup.POST("/login", tokenHandler.Login)
	tokenGroup.GET("/secure", tokenHandler.Secured)

	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	r.Run(":8080")
}
