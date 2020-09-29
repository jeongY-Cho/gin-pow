package ginpow

import (
	"encoding/hex"
	"errors"
	"strconv"

	"github.com/gin-gonic/gin"
	gopow "github.com/jeongy-cho/go-pow/v2"
	gonanoid "github.com/matoous/go-nanoid"
)

// Middleware provides a proof of work implementation. On failure, an error 428 response is returned.
// On success, the middleware passes to the next handler. Clients can request a nonce by posting a json
// or xml request to NonceHandler, or by reading the set headers on an endpoint that uses the NonceHeaderMiddleware
type Middleware struct {
	// NonceHeader is the name of the header on which to set a generated nonce.
	//   Defaults to `X-Nonce`
	NonceHeader string

	// NonceChecksumHeader is the name of the header on which to set a generated nonce.
	//   Defaults to `X-Nonce-Checksum`
	NonceChecksumHeader string

	// HashDifficultyHeader is the name of the header on which to set the difficulty.
	//   Defaults to `X-Hash-Difficulty`
	HashDifficultyHeader string

	// Pow is a gopow.Pow instance to handle proof of work implementation
	Pow *gopow.Pow

	// ExtractAll extracts all necessary data at once.
	//   Optional. If not set then uses the default methods defined in `ExtractData`,
	//   `ExtractNonce`, and `ExtractHash`. When ExtractAll is set, then `ExtractData`,
	//   `ExctractNonce`, `ExtractHash` is ignored.
	ExtractAll func(c *gin.Context) (nonce string, nonceChecksum string, data string, hash string, err error)

	// ExtractData extracts the data that the hash was generated against and
	//   passes it to do proof of work calculation.
	//   Required when `ExtractAll` isn't defined.
	ExtractData func(c *gin.Context) (string, error)

	// ExtractNonce extracts the nonce that is in the request.
	//   Defaults getting from header X-Nonce, X-Nonce-Checksum
	ExtractNonce func(c *gin.Context) (nonce string, nonceChecksum string, error error)

	// ExtractHash extracts the calculated hash calculated by the client.
	//   Defaults to getting from header X-Hash.
	ExtractHash func(c *gin.Context) (hash string, error error)

	// Difficulty sets the number of leading zeros required for a valid hash.
	//   Defaults to 0.
	Difficulty int

	// NonceLength sets the length of the nonce to be generated
	//   Defaults to 10.
	NonceLength int

	// Check is the flag to enable nonce checking
	//   Defaults to false.
	Check bool

	// Secret is a cryptographically secure random string to generate nonce checksums.
	//   only used when `Check` flag is true. Defaults to 256 bit cryptographically secure string.
	Secret string

	// the following is the keys in which to set nonces in gin.Context.
	// Defaults:
	//   NonceContextKey:          "nonce"
	//   NonceChecksumContextKey:  "nonceChecksum"
	//   HashDifficultyContextKey: "hashDifficulty"
	NonceContextKey          string
	NonceChecksumContextKey  string
	HashDifficultyContextKey string

	// the following is the keys in which to set nonces in data of Middleware.NonceHandler.
	// Defaults:
	//   NonceDataKey:          "nonce"
	//   NonceChecksumDataKey:  "nonce_checksum"
	//   HashDifficultyDataKey: "difficulty"
	NonceDataKey          string
	NonceChecksumDataKey  string
	HashDifficultyDataKey string

	// FailureStatusCode is the status code to send back to client
	//   when using default OnFailedVerification. defaults to 428.
	FailureStatusCode int

	// OnFailedVerification is called when a hash validation fails.
	//   By default request Aborts and returns with `Middleware.FailureStatusCode`.
	OnFailedVerification func(c *gin.Context, err *VerificationError)

	// Hash function for proof of work.
	//   Defaults to sha256
	Hash gopow.HashFunction

	// NonceGenerator returns a nonce.
	NonceGenerator gopow.NonceGenerator
}

// New sets the config of a middleware. ExtractData definition is required.
func New(m *Middleware) (*Middleware, error) {
	if err := m.middleWareInit(); err != nil {
		return nil, err
	}
	return m, nil
}

func (pow *Middleware) middleWareInit() error {
	if pow.ExtractData == nil && pow.ExtractAll == nil {
		return errors.New("pow.ExtractData func not declared")
	}

	if pow.NonceHeader == "" {
		pow.NonceHeader = "X-Nonce"
	}

	if pow.NonceChecksumHeader == "" {
		pow.NonceChecksumHeader = "X-Nonce-Checksum"
	}

	if pow.HashDifficultyHeader == "" {
		pow.HashDifficultyHeader = "X-Hash-Difficulty"
	}

	if pow.ExtractNonce == nil {
		pow.ExtractNonce = func(c *gin.Context) (nonce string, nonceChecksum string, err error) {
			return c.GetHeader("X-Nonce"), c.GetHeader("X-Nonce-Checksum"), nil
		}
	}

	if pow.ExtractHash == nil {
		pow.ExtractHash = func(c *gin.Context) (hash string, error error) {
			return c.GetHeader("X-Hash"), nil
		}
	}

	if pow.Check {
		if pow.Secret == "" {
			var err error
			pow.Secret, err = gonanoid.ID(32)
			if err != nil {
				return err
			}
		}
	}

	if pow.NonceLength == 0 {
		pow.NonceLength = 10
	}

	pow.Pow = gopow.New(&gopow.Pow{
		Secret:         []byte(pow.Secret),
		Check:          pow.Check,
		Difficulty:     pow.Difficulty,
		NonceLength:    pow.NonceLength,
		Hash:           pow.Hash,
		NonceGenerator: pow.NonceGenerator,
	})

	if pow.NonceContextKey == "" {
		pow.NonceContextKey = "nonce"
	}

	if pow.NonceChecksumContextKey == "" {
		pow.NonceChecksumContextKey = "nonceChecksum"
	}

	if pow.HashDifficultyContextKey == "" {
		pow.HashDifficultyContextKey = "hashDifficulty"
	}

	if pow.NonceDataKey == "" {
		pow.NonceDataKey = "nonce"
	}

	if pow.NonceChecksumDataKey == "" {
		pow.NonceChecksumDataKey = "nonce_checksum"
	}

	if pow.HashDifficultyDataKey == "" {
		pow.HashDifficultyDataKey = "difficulty"
	}

	if pow.FailureStatusCode == 0 {
		pow.FailureStatusCode = 428
	}

	if pow.OnFailedVerification == nil {
		pow.OnFailedVerification = func(c *gin.Context, err *VerificationError) {
			c.Abort()
			c.String(pow.FailureStatusCode, err.Error())
		}
	}

	return nil

}

// NonceHandler is the used by a client to get a nonce in JSON or XML depending on accept header
func (pow *Middleware) NonceHandler(c *gin.Context) {
	nonce, nonceChecksum, err := pow.getNonce(c)
	if err != nil {
		c.Error(err)
		return
	}

	var h gin.H
	h = gin.H{
		pow.NonceDataKey:          nonce,
		pow.HashDifficultyDataKey: pow.Difficulty,
	}

	if pow.Check {
		h[pow.NonceChecksumDataKey] = nonceChecksum
	}
	c.Negotiate(200, gin.Negotiate{
		Offered: []string{gin.MIMEJSON, gin.MIMEXML},
		Data:    h,
	})
}

// NonceHeaderMiddleware is used by a client to get a nonce embedded in the header of a request
func (pow *Middleware) NonceHeaderMiddleware(c *gin.Context) {
	nonce, nonceChecksum, err := pow.getNonce(c)
	if err != nil {
		c.Error(err)
		return
	}

	c.Header(pow.NonceHeader, nonce)
	c.Header(pow.HashDifficultyHeader, strconv.Itoa(pow.Difficulty))
	if pow.Check {
		c.Header(pow.NonceChecksumHeader, nonceChecksum)
	}
}

// GenerateNonceMiddleware generates a nonce and sets it in the context.
// if other ginpow middleware is used after this middleware then it will
// use the nonce generated here.
func (pow *Middleware) GenerateNonceMiddleware(c *gin.Context) {
	nonce, nonceChecksum, err := pow.Pow.GenerateNonce()
	if err != nil {
		c.Error(err)
		return
	}

	c.Set(pow.NonceContextKey, string(nonce))
	c.Set(pow.HashDifficultyContextKey, pow.Difficulty)

	if pow.Check {
		c.Set(pow.NonceChecksumContextKey, hex.EncodeToString(nonceChecksum))
	}
}

// gets a nonce in context or generates one
func (pow *Middleware) getNonce(c *gin.Context) (string, string, error) {

	n, nExists := c.Get(pow.NonceContextKey)
	nc, _ := c.Get(pow.NonceChecksumContextKey)

	if nExists {
		if pow.Check {
			return n.(string), nc.(string), nil
		}
		return n.(string), "", nil
	}

	nonce, nonceChecksum, err := pow.Pow.GenerateNonce()
	return string(nonce), hex.EncodeToString(nonceChecksum), err
}

// VerifyNonceMiddleware validates a hash given a nonce, data string, difficulty,
// and, if `Middleware.Check == true`, nonce checksum. On failure, it will call
// OnVerifiedFailed method. By default will Abort response with status code 428
func (pow *Middleware) VerifyNonceMiddleware(c *gin.Context) {
	var (
		nonce         string
		nonceChecksum string
		data          string
		hash          string
		err           error
	)

	if pow.ExtractAll != nil {
		nonce, nonceChecksum, data, hash, err = pow.ExtractAll(c)
		if err != nil {
			if !c.IsAborted() {
				c.AbortWithError(500, err)
			}
			return
		}
	} else {
		nonce, nonceChecksum, err = pow.ExtractNonce(c)
		if err != nil {
			if !c.IsAborted() {
				c.AbortWithError(500, err)
			}
			return
		}

		if nonce == "" {
			c.String(400, "no nonce in request")
			c.Abort()
			return
		}

		if pow.Check && nonceChecksum == "" {
			c.String(400, "no nonce checksum in request")
			c.Abort()
			return
		}

		data, err = pow.ExtractData(c)
		if err != nil {
			if !c.IsAborted() {
				c.AbortWithError(500, err)
			}
			return
		}

		hash, err = pow.ExtractHash(c)
		if err != nil {
			if !c.IsAborted() {
				c.AbortWithError(500, err)
			}
			return
		}

		if hash == "" {
			c.String(400, "no hash in request")
			c.Abort()
			return
		}
	}
	hashBytes, err := hex.DecodeString(hash)
	if err != nil {
		c.String(400, "received hash is not a valid hex string")
		c.Abort()
		return
	}

	nonceChecksumBytes, err := hex.DecodeString(nonceChecksum)
	if err != nil {
		c.String(400, "received checksum is not a valid hex string")
		c.Abort()
		return
	}

	ok, verificationErr := pow.Pow.VerifyHashAtDifficulty([]byte(nonce), []byte(data), hashBytes, nonceChecksumBytes)
	if !ok {
		err := &VerificationError{
			Hash:          hash,
			Nonce:         nonce,
			NonceChecksum: nonceChecksum,
			Difficulty:    pow.Difficulty,
			Reason:        verificationErr.Error(),
		}
		c.Error(err)
		pow.OnFailedVerification(c, err)
	}
}

// VerificationError reports the parameters that caused a verification to fail.
// Does _not_ include data parameter.
type VerificationError struct {
	Hash          string
	Nonce         string
	NonceChecksum string
	Difficulty    int
	Reason        string
}

func (v *VerificationError) Error() string {
	return v.Reason
}

type headerGetter interface {
	GetHeader(key string) string
}
