package main

import (
	"go-jwt/controller"
	"go-jwt/initializers"
	"go-jwt/middleware"

	"github.com/gin-gonic/gin"
)

func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectToDB()
	initializers.SyncDatabase()
}

func main() {

	r := gin.Default()

//Routes users
	r.POST("/Register", controller.Register)
	r.POST("/Login", controller.Login)
	r.GET("/IndexUser", controller.GetUser)
	r.GET("/ShowUser/:id", controller.ShowUser)
	r.PUT("/UpdateUser/:id", controller.UpdateUser)
	r.DELETE("/DeleteUser/:id", controller.DeleteUser)
	r.GET("/Validate", middleware.RequireAuth, controller.Validate)

	r.Run()
}
