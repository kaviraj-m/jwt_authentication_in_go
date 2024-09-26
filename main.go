package main

import (
	"net/http"
	"time"
	"github.com/gin-gonic/gin"
	"github.com/dgrijalva/jwt-go"
)

// Secret key for JWT
var jwtSecret = []byte("mySuperSecretKey12345")

// Mock database
var users = map[string]string{
	"admin": "password123",
}

// Struct for login request
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// JWT claims structure
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// Middleware to authenticate JWT
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		// Remove 'Bearer ' prefix if present
		if len(tokenString) > len("Bearer ") && tokenString[:len("Bearer ")] == "Bearer " {
			tokenString = tokenString[len("Bearer "):]
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token format"})
			c.Abort()
			return
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Failed to parse token: " + err.Error()})
			c.Abort()
			return
		}

		if !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		c.Set("username", claims.Username)
		c.Next()
	}
}

func main() {
	router := gin.Default()

	// Public route for login
	router.POST("/login", login)

	// Protected route group
	protected := router.Group("/api/v1")
	protected.Use(authMiddleware())
	{
		protected.GET("/", welcome)
	}

	// Start the server
	router.Run(":8080")
}

// Login route handler
func login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	if password, exists := users[req.Username]; !exists || password != req.Password {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Username: req.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

// Protected route handler
func welcome(c *gin.Context) {
	username, _ := c.Get("username")
	c.JSON(http.StatusOK, gin.H{
		"message": "Welcome to the authenticated Gin backend!",
		"user":    username,
	})
}
