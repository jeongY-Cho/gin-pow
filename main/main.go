package main

import (
	"github.com/gin-gonic/gin"
	ginpow "github.com/jeongy-cho/gin-pow"
)

func main() {
	router := gin.Default()

	pow, _ := ginpow.New(&ginpow.Middleware{
		Check:       true,
		ExtractData: func(c *gin.Context) (string, error) { return "a", nil },
		Difficulty:  1,
	})

	router.Use(pow.GenerateNonceMiddleware, pow.NonceHeaderMiddleware, pow.NonceHandler)

	router.Run()
}
