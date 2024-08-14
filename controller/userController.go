package controller

import (
	"go-jwt/initializers"
	"go-jwt/models"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

func Register(c *gin.Context) {

	//Get the email/password from the request
	var body struct {
		Email    string
		Password string
	}

	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read body",
		})

		return
	}

	//Hash the password
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to hash password",
		})
		return
	}

	//Create the user
	user := models.User{Email: body.Email, Password: string(hash)}
	result := initializers.DB.Create(&user)

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create user",
		})
	}

	//Send back the response

	c.JSON(http.StatusOK, gin.H{
		"message": "User created successfully",
	})
}

func Login(c *gin.Context) {
	//Get the email/password from the request
	var body struct {
		Email    string
		Password string
	}

	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read body",
		})

		return
	}

	//Look up requested user
	var user models.User
	initializers.DB.First(&user, "email = ?", body.Email)

	if user.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid email",
		})

		return
	}

	//Compare password
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid password",
		})

		return
	}

	//Generate JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Hour * 24 * 30).Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create token",
		})
	}

	// //Send back the response
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("Authorization", tokenString, 3600*24*30, "", "", false, true)

	c.JSON(http.StatusOK, gin.H{})
}

func Validate(c *gin.Context) {
	user, _ := c.Get("user")

	c.JSON(http.StatusOK, gin.H{
		"message": user,
	})

}

func GetUser(c *gin.Context) {

	// Get models from DB
	var user []models.User
	initializers.DB.Find(&user)

	//Respond with them
	c.JSON(200, gin.H{
		"Iso": user,
	})
}

func ShowUser(c *gin.Context) {
	id := c.Param("id")

	var users models.User

	if err := initializers.DB.First(&users, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, users)
}

func UpdateUser(c *gin.Context) {
	var body struct {
		Email    string
		Password string
	}

	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read body",
		})
		return
	}

	//hash the password
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to hash password",
		})
		return
	}

	// Get the Id from the URL parameters
	id := c.Param("id")

	// Find the post we are updating
	var user models.User

	if err := initializers.DB.First(&user, id).Error; err != nil {
		c.JSON(404, gin.H{"error": "User not found"})
		return
	}

	// Update the post
	if err := initializers.DB.Model(&user).Updates(models.User{
		Email:    body.Email,
		Password: string(hash),
	}).Error; err != nil {
		c.JSON(500, gin.H{"error": "Failed to update user: " + err.Error()})
		return
	}

	// Respond with the updated post
	c.JSON(200, gin.H{
		"user": user,
	})
}

func DeleteUser(c *gin.Context) {
	id := c.Param("id")	

	initializers.DB.Delete(&models.User{}, id)

	c.JSON(200, gin.H{
		"message": "User deleted successfully",
	})
}