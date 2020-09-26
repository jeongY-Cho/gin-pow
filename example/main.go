package main

import (
	"github.com/gin-gonic/gin"
	ginpow "github.com/jeongy-cho/gin-pow"
)

func main() {
	router := gin.Default()

	pow, _ := ginpow.New(&ginpow.Middleware{
		Check: true,
		ExtractData: func(c *gin.Context) (string, error) {
			return c.GetHeader("X-Data"), nil
		},
		Difficulty: 1,
	})

	router.GET("/nonce/same", pow.GenerateNonceMiddleware, pow.NonceHeaderMiddleware, pow.NonceHandler)
	router.GET("/nonce/different", pow.NonceHeaderMiddleware, pow.NonceHandler)
	router.GET("/hash/verify", pow.VerifyNonceMiddleware)

	router.Run()
}
