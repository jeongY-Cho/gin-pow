package main

import (
	"fmt"
	"strconv"

	"github.com/gin-gonic/gin"
	ginpow "github.com/jeongy-cho/gin-pow"
)

func main() {
	router := gin.Default()

	pow, _ := ginpow.New(&ginpow.Middleware{
		Check:  true,
		Secret: "secret",
		ExtractAll: func(c *gin.Context) (nonce string, nonceChecksum string, data string, hash string, err error) {
			var j gin.H
			c.BindJSON(&j)

			nonce = j["nonce"].(string)
			nonceChecksum = j["nonce_checksum"].(string)
			data = fmt.Sprintf("%.f", j["counter"].(float64))
			hash = j["hash"].(string)
			return
		},
		Difficulty: 11,
	})
	pow2, _ := ginpow.New(&ginpow.Middleware{
		ExtractAll: func(c *gin.Context) (nonce string, nonceChecksum string, data string, hash string, err error) {
			var j gin.H
			c.BindJSON(&j)

			nonce = j["nonce"].(string)
			data = j["username"].(string) + j["password"].(string)
			hash = j["hash"].(string)
			return
		},
		Difficulty: 10,
	})

	router.StaticFile("/", "./index.html")
	router.GET("/nonce/issue", pow.NonceHandler)
	router.POST("/hash/verify", pow.VerifyNonceMiddleware, func(c *gin.Context) {
		c.String(200, "yay hash is good!")
	})
	router.POST("/login", pow2.VerifyNonceMiddleware, func(c *gin.Context) {
		c.String(200, "yay logged in!")
	})
	router.GET("/login", func(c *gin.Context) {
		c.String(200, strconv.Itoa(pow2.Pow.Difficulty))
	})

	router.Run()
}
