package ginpow

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	gopow "github.com/jeongy-cho/go-pow/v2"
	gonanoid "github.com/matoous/go-nanoid"
)

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	m.Run()
	rand.Seed(time.Now().Unix())
}

func TestNew(t *testing.T) {
	defaultMiddleware := &Middleware{
		NonceHeader:              "X-Nonce",
		NonceChecksumHeader:      "X-Nonce-Checksum",
		HashDifficultyHeader:     "X-Hash-Difficulty",
		Pow:                      &gopow.Pow{NonceLength: 10},
		Difficulty:               0,
		NonceLength:              10,
		Check:                    false,
		Secret:                   "",
		NonceContextKey:          "nonce",
		NonceChecksumContextKey:  "nonceChecksum",
		HashDifficultyContextKey: "hashDifficulty",
		NonceDataKey:             "nonce",
		NonceChecksumDataKey:     "nonce_checksum",
		HashDifficultyDataKey:    "difficulty",
		FailureStatusCode:        428,
		ExtractData:              func(c *gin.Context) (string, error) { return "d", nil },
	}

	t.Run("test defaults, no ExtractData", func(t *testing.T) {
		_, err := New(&Middleware{})

		if err == nil {
			t.Error("New() did not error when ExtractData is not set")
		}
	})

	t.Run("test defaults, no ExtractData, but ExtractAll", func(t *testing.T) {
		_, err := New(&Middleware{
			ExtractAll: func(c *gin.Context) (nonce string, nonceChecksum string, data string, hash string, err error) { return },
		})

		if err != nil {
			t.Error("New() did error when ExtractData is not set")
		}
	})

	t.Run("test default properties", func(t *testing.T) {
		newMiddleware := &Middleware{
			ExtractData: func(c *gin.Context) (string, error) { return "", nil },
		}
		newMiddleware, err := New(newMiddleware)
		if err != nil {
			t.Errorf("New() returned error: %v", err)
		}
		e := reflect.ValueOf(newMiddleware).Elem()
		d := reflect.ValueOf(defaultMiddleware).Elem()
		for i := 0; i < e.NumField(); i++ {
			varName := e.Type().Field(i).Name
			varType := e.Type().Field(i).Type
			varKind := varType.Kind()
			if varKind == reflect.Func {
				continue
			}

			if varName == "Pow" {
				continue
			}

			dvar, _ := d.Type().FieldByName(varName)

			varValue := e.Field(i).Interface()
			dval := d.FieldByName(dvar.Name).Interface()

			if !reflect.DeepEqual(varValue, dval) {
				t.Errorf("%v is not equal to test default", varName)
			}
		}
	})

	t.Run("test default methods", func(t *testing.T) {
		newMiddleware, _ := New(&Middleware{
			ExtractData: func(c *gin.Context) (string, error) { return "", nil },
		})

		e := reflect.ValueOf(newMiddleware).Elem()
		funcNames := make(map[string]int, 0)
		ignoreMethods := map[string]int{
			"ExtractData":    1,
			"Hash":           1,
			"NonceGenerator": 1,
			"ExtractAll":     1,
		}
		// get all methods
		for i := 0; i < e.NumField(); i++ {
			if e.Type().Field(i).Type.Kind() == reflect.Func {
				mName := e.Type().Field(i).Name
				if _, ignore := ignoreMethods[mName]; !ignore {
					funcNames[e.Type().Field(i).Name] = 1
				}
			}
		}

		t.Run("default ExtractNonce", func(t *testing.T) {
			newMiddleware, _ := New(&Middleware{
				ExtractData: func(c *gin.Context) (string, error) { return "", nil },
			})
			req := httptest.NewRequest("GET", "/", nil)

			testNonce, _ := gonanoid.Nanoid()
			mockChecksum, _ := gonanoid.ID(32)
			req.Header.Set("X-Nonce", testNonce)
			req.Header.Set("X-Nonce-Checksum", mockChecksum)

			w := httptest.NewRecorder()

			c, _ := gin.CreateTestContext(w)

			c.Request = req

			headerNonce, headerChecksum, _ := newMiddleware.ExtractNonce(c)
			if headerNonce != testNonce {
				t.Errorf("Nonce header not equal; Got: %v, Expected: %v", headerNonce, testNonce)
			}

			if headerChecksum != mockChecksum {
				t.Errorf("checksum header not equal; Got: %v, Expected: %v", headerChecksum, mockChecksum)
			}

			if !t.Failed() {
				delete(funcNames, "ExtractNonce")
			}
		})

		t.Run("default ExtractHash", func(t *testing.T) {
			newMiddleware, _ := New(&Middleware{
				ExtractData: func(c *gin.Context) (string, error) { return "", nil },
			})
			req := httptest.NewRequest("GET", "/", nil)

			testHash, _ := gonanoid.ID(32)
			req.Header.Set("X-Hash", testHash)

			w := httptest.NewRecorder()

			c, _ := gin.CreateTestContext(w)

			c.Request = req

			headerHash, _ := newMiddleware.ExtractHash(c)
			if headerHash != testHash {
				t.Errorf("Nonce header not equal; Got: %v, Expected: %v", headerHash, testHash)
			}

			if !t.Failed() {
				delete(funcNames, "ExtractHash")
			}
		})

		t.Run("default OnFailedVerification", func(t *testing.T) {
			newMiddleware, _ := New(&Middleware{
				ExtractData: func(c *gin.Context) (string, error) { return "", nil },
			})

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			newMiddleware.OnFailedVerification(c, &VerificationError{})

			if expect := 428; w.Code != expect {
				t.Errorf("default OnFailedVerification did not return %v, instead: %v", expect, w.Code)
			}

			if !t.Failed() {
				delete(funcNames, "OnFailedVerification")
			}
		})

		if len(funcNames) != 0 {
			t.Errorf("Untested default methods: %v", funcNames)
		}

	})

	t.Run("default with check", func(t *testing.T) {
		newMiddleware, err := New(&Middleware{
			ExtractData: func(c *gin.Context) (string, error) { return "", nil },
			Check:       true,
		})
		if err != nil {
			t.Error("New threw error when making default with check")
		}

		if newMiddleware.Secret == "" {
			t.Error("New() did not generate random secret")
		}

		if l := len(newMiddleware.Secret); l != 32 {
			t.Errorf("generated secret is not 32 bytes, instead: %v", l)
		}
	})
}

func TestMiddleware_NonceHandler(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		t.Run("no check", func(t *testing.T) {
			m, _ := New(&Middleware{
				ExtractData: func(c *gin.Context) (string, error) { return "", nil },
			})
			w := httptest.NewRecorder()

			c, _ := gin.CreateTestContext(w)
			c.Accepted = []string{gin.MIMEJSON}

			m.NonceHandler(c)

			var j map[string]interface{}
			json.Unmarshal(w.Body.Bytes(), &j)

			nonce, nonceOk := j["nonce"]
			if !nonceOk {
				t.Error("nonce not returned")
			}
			d, dOk := j["difficulty"]
			if !dOk {
				t.Error("difficulty not returned")
			}

			if expect := 10; len(nonce.(string)) != expect {
				t.Errorf("nonce is not default length %v, instead: %v", expect, nonce)
			}

			if expect := float64(0); d.(float64) != expect {
				t.Errorf("difficulty is not default %v, instead: %v", expect, nonce)
			}

		})
		t.Run("check", func(t *testing.T) {
			testSecret := "test"
			m, _ := New(&Middleware{
				ExtractData: func(c *gin.Context) (string, error) { return "", nil },
				Check:       true,
				Secret:      testSecret,
			})
			w := httptest.NewRecorder()

			c, _ := gin.CreateTestContext(w)
			c.Accepted = []string{gin.MIMEJSON}

			m.NonceHandler(c)

			var j map[string]interface{}

			json.Unmarshal(w.Body.Bytes(), &j)

			nonce, nonceOk := j["nonce"]
			if !nonceOk {
				t.Error("nonce not returned")
			}
			d, dOk := j["difficulty"]
			if !dOk {
				t.Error("difficulty not returned")
			}

			cs, csOk := j["nonce_checksum"]
			if !csOk {
				t.Error("nonce_checksum not returned")
			}

			if expect := 10; len(nonce.(string)) != expect {
				t.Errorf("nonce is not default length %v, instead: %v", expect, nonce)
			}

			if expect := float64(0); d.(float64) != expect {
				t.Errorf("difficulty is not default %v, instead: %v", expect, nonce)
			}

			calcHash := sha256.Sum256([]byte(nonce.(string) + testSecret))
			if expect := hex.EncodeToString(calcHash[:]); cs != expect {
				t.Errorf("checksum is not correct %v, instead: %v", expect, cs)
			}

		})

	})

	t.Run("test custom fields", func(t *testing.T) {
		nonceKey, _ := gonanoid.Nanoid()
		nonceChecksumKey, _ := gonanoid.Nanoid()
		hashDifficultyKey, _ := gonanoid.Nanoid()

		m, _ := New(&Middleware{
			ExtractData:           func(c *gin.Context) (string, error) { return "", nil },
			NonceDataKey:          nonceKey,
			NonceChecksumDataKey:  nonceChecksumKey,
			HashDifficultyDataKey: hashDifficultyKey,
			Check:                 true,
		})
		w := httptest.NewRecorder()

		c, _ := gin.CreateTestContext(w)
		c.Accepted = []string{gin.MIMEJSON}

		m.NonceHandler(c)

		var j map[string]interface{}

		json.Unmarshal(w.Body.Bytes(), &j)

		_, nonceOk := j[nonceKey]
		if !nonceOk {
			t.Error("nonce not returned")
		}

		_, dOk := j[hashDifficultyKey]
		if !dOk {
			t.Error("difficulty not returned")
		}

		_, csOk := j[nonceChecksumKey]
		if !csOk {
			t.Error("nonce_checksum not returned")
		}
	})

	t.Run("test difficulty config", func(t *testing.T) {
		testDifConfig := rand.Intn(10)

		m, _ := New(&Middleware{
			ExtractData: func(c *gin.Context) (string, error) { return "", nil },
			Difficulty:  testDifConfig,
			Check:       true,
		})
		w := httptest.NewRecorder()

		c, _ := gin.CreateTestContext(w)
		c.Accepted = []string{gin.MIMEJSON}

		m.NonceHandler(c)

		var j map[string]interface{}

		json.Unmarshal(w.Body.Bytes(), &j)

		if j["difficulty"] != float64(testDifConfig) {
			t.Errorf("returned difficulty not set to configured; Got: %#v, Expected: %#v", j["difficulty"], testDifConfig)
		}

	})

}

func TestMiddleware_NonceHeaderMiddleware(t *testing.T) {
	t.Run("no check", func(t *testing.T) {
		m, _ := New(&Middleware{
			ExtractData: func(c *gin.Context) (string, error) { return "", nil },
		})
		w := httptest.NewRecorder()

		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("", "/", nil)

		m.NonceHeaderMiddleware(c)

		xNonce := w.Result().Header.Get("X-Nonce")
		xNonceChecksum := w.Result().Header.Get("X-Nonce-Checksum")
		xHashDifficulty := w.Result().Header.Get("X-Hash-Difficulty")

		if xNonce == "" {
			t.Error("no X-Nonce header")
		}

		if xHashDifficulty == "" {
			t.Error("no X-Hash-Difficulty")
		}

		if xNonceChecksum != "" {
			t.Errorf("some checksome returned: %v", xNonceChecksum)
		}

	})

	t.Run("check", func(t *testing.T) {
		m, _ := New(&Middleware{
			ExtractData: func(c *gin.Context) (string, error) { return "", nil },
			Check:       true,
		})
		w := httptest.NewRecorder()

		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("", "/", nil)

		m.NonceHeaderMiddleware(c)
		xNonce := w.Result().Header.Get("X-Nonce")
		xNonceChecksum := w.Result().Header.Get("X-Nonce-Checksum")
		xHashDifficulty := w.Result().Header.Get("X-Hash-Difficulty")

		if xNonce == "" {
			t.Error("no X-Nonce header")
		}

		if xHashDifficulty == "" {
			t.Error("no X-Hash-Difficulty")
		}

		if xNonceChecksum == "" {
			t.Error("no X-Nonce-Checksum")
		}
	})

	t.Run("custom headers", func(t *testing.T) {
		nonceHeader, _ := gonanoid.Nanoid()
		nonceChecksumHeader, _ := gonanoid.Nanoid()
		hashDifficultyHeader, _ := gonanoid.Nanoid()

		m, _ := New(&Middleware{
			ExtractData:          func(c *gin.Context) (string, error) { return "", nil },
			Check:                true,
			NonceHeader:          nonceHeader,
			NonceChecksumHeader:  nonceChecksumHeader,
			HashDifficultyHeader: hashDifficultyHeader,
		})
		w := httptest.NewRecorder()

		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("", "/", nil)

		m.NonceHeaderMiddleware(c)
		xNonce := w.Result().Header.Get(nonceHeader)
		xNonceChecksum := w.Result().Header.Get(nonceChecksumHeader)
		xHashDifficulty := w.Result().Header.Get(hashDifficultyHeader)

		if xNonce == "" {
			t.Error("no Nonce header")
		}

		if xHashDifficulty == "" {
			t.Error("no Difficulty header")
		}

		if xNonceChecksum == "" {
			t.Error("no X-Nonce-Checksum header")
		}
	})

	t.Run("check difficulty config", func(t *testing.T) {
		testDifficulty := rand.Intn(20)
		m, _ := New(&Middleware{
			ExtractData: func(c *gin.Context) (string, error) { return "", nil },
			Check:       true,
			Difficulty:  testDifficulty,
		})
		w := httptest.NewRecorder()

		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("", "/", nil)

		m.NonceHeaderMiddleware(c)
		xHashDifficulty := w.Result().Header.Get("X-Hash-Difficulty")

		if d, _ := strconv.Atoi(xHashDifficulty); d != testDifficulty {
			t.Errorf("returned difficulty not equal to set difficulty; Got: %#v, Expected: %#v", d, testDifficulty)
		}

	})
}

func TestMiddleware_GenerateNonceMiddleWare(t *testing.T) {
	t.Run("test Default", func(t *testing.T) {
		t.Run("check", func(t *testing.T) {
			m, _ := New(&Middleware{
				ExtractData: func(c *gin.Context) (string, error) { return "", nil },
				Check:       true,
			})
			w := httptest.NewRecorder()

			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("", "/", nil)

			m.GenerateNonceMiddleware(c)
			_, nExists := c.Get("nonce")
			_, ncExists := c.Get("nonceChecksum")

			if !nExists {
				t.Error("nonce not set")
			}

			if !ncExists {
				t.Error("nonceChecksum not set")
			}
		})
		t.Run("no check", func(t *testing.T) {
			m, _ := New(&Middleware{
				ExtractData: func(c *gin.Context) (string, error) { return "", nil },
			})
			w := httptest.NewRecorder()

			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("", "/", nil)

			m.GenerateNonceMiddleware(c)
			_, nExists := c.Get("nonce")
			_, ncExists := c.Get("nonceChecksum")

			if !nExists {
				t.Error("nonce not set")
			}

			if ncExists {
				t.Error("nonceChecksum is set")
			}
		})
	})
	t.Run("test custom", func(t *testing.T) {
		nonceKey, _ := gonanoid.Nanoid()
		nonceChecksumKey, _ := gonanoid.Nanoid()

		m, _ := New(&Middleware{
			ExtractData:             func(c *gin.Context) (string, error) { return "", nil },
			Check:                   true,
			NonceContextKey:         nonceKey,
			NonceChecksumContextKey: nonceChecksumKey,
		})
		w := httptest.NewRecorder()

		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("", "/", nil)

		m.GenerateNonceMiddleware(c)

		if _, exists := c.Get(nonceKey); !exists {
			t.Error("nonce not set to key: " + nonceKey)
		}

		if _, exists := c.Get(nonceChecksumKey); !exists {
			t.Error("nonce checksum not set to key: " + nonceChecksumKey)
		}
	})
	t.Run("test twice", func(t *testing.T) {
		nonceKey, _ := gonanoid.Nanoid()
		nonceChecksumKey, _ := gonanoid.Nanoid()

		m, _ := New(&Middleware{
			ExtractData:             func(c *gin.Context) (string, error) { return "", nil },
			Check:                   true,
			NonceContextKey:         nonceKey,
			NonceChecksumContextKey: nonceChecksumKey,
		})
		w := httptest.NewRecorder()

		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("", "/", nil)

		m.GenerateNonceMiddleware(c)
		n1, _ := c.Get(nonceKey)
		nc1, _ := c.Get(nonceKey)

		m.GenerateNonceMiddleware(c)
		n2, _ := c.Get(nonceKey)
		nc2, _ := c.Get(nonceKey)

		if n1 == n2 {
			t.Errorf("first and second nonces are equal: %v", n1)
		}

		if nc1 == nc2 {
			t.Errorf("first and second nonceChecksums are equal: %v", nc1)
		}

	})
}

func TestMiddleware_getNonce(t *testing.T) {
	t.Run("check", func(t *testing.T) {
		nonceKey, _ := gonanoid.Nanoid()
		nonceChecksumKey, _ := gonanoid.Nanoid()

		m, _ := New(&Middleware{
			ExtractData:             func(c *gin.Context) (string, error) { return "", nil },
			Check:                   true,
			NonceContextKey:         nonceKey,
			NonceChecksumContextKey: nonceChecksumKey,
		})
		w := httptest.NewRecorder()

		c, _ := gin.CreateTestContext(w)

		m.GenerateNonceMiddleware(c)
		n1, _ := c.Get(nonceKey)
		nc1, _ := c.Get(nonceChecksumKey)

		n2, nc2, _ := m.getNonce(c)

		if !reflect.DeepEqual(n1, n2) {
			t.Errorf("got different nonces; Got: %v, Expected: %v", n1, n2)
		}
		if !reflect.DeepEqual(nc1, nc2) {
			t.Errorf("got different nonce checksum; Got: %v, Expected: %v", nc1, nc2)
		}

	})
	t.Run("no check", func(t *testing.T) {
		nonceKey, _ := gonanoid.Nanoid()
		nonceChecksumKey, _ := gonanoid.Nanoid()

		m, _ := New(&Middleware{
			ExtractData:             func(c *gin.Context) (string, error) { return "", nil },
			NonceContextKey:         nonceKey,
			NonceChecksumContextKey: nonceChecksumKey,
		})
		w := httptest.NewRecorder()

		c, _ := gin.CreateTestContext(w)

		m.GenerateNonceMiddleware(c)
		n1, _ := c.Get(nonceKey)

		n2, nc2, _ := m.getNonce(c)

		if !reflect.DeepEqual(n1, n2) {
			t.Errorf("got different nonces; Got: %v, Expected: %v", n1, n2)
		}

		if !reflect.DeepEqual(nc2, "") {
			t.Errorf("got a nonce checksum when shouldn't have: %#v", nc2)
		}
	})
}

func TestMiddleware_VerifyNonceMiddleware(t *testing.T) {
	t.Run("check, difficulty 0", func(t *testing.T) {
		m, _ := New(&Middleware{
			Check:       true,
			Secret:      "secret",
			ExtractData: func(c *gin.Context) (string, error) { return "data", nil },
			ExtractHash: func(c *gin.Context) (hash string, error error) {
				hash = "2c177eecd4ad52094136dff33d30163ff0e47a95934a5c3e95abbade8700cdfd"
				return
			},
			ExtractNonce: func(c *gin.Context) (nonce string, nonceChecksum string, error error) {
				nonce = "nonce"
				nonceChecksum = "5c420d7fedeb75e1309b1fe82f9c85d5552f1edfc11c72e7749330881166f18d"
				return
			},
		})
		w := httptest.NewRecorder()

		c, _ := gin.CreateTestContext(w)

		m.VerifyNonceMiddleware(c)

		if len(c.Errors) > 0 {
			t.Errorf("verification failed with error: %v", c.Errors)
		}
	})

	t.Run("check, difficulty 1", func(t *testing.T) {
		m, _ := New(&Middleware{
			Difficulty:  1,
			Check:       true,
			Secret:      "secret",
			ExtractData: func(c *gin.Context) (string, error) { return "data11111", nil },
			ExtractHash: func(c *gin.Context) (hash string, error error) {
				hash = "024b6380e07b20023e1b986b250b09bcfaa4551510ac4903a9b052e2b2cf9019"
				return
			},
			ExtractNonce: func(c *gin.Context) (nonce string, nonceChecksum string, error error) {
				nonce = "nonce"
				nonceChecksum = "5c420d7fedeb75e1309b1fe82f9c85d5552f1edfc11c72e7749330881166f18d"
				return
			},
		})
		w := httptest.NewRecorder()

		c, _ := gin.CreateTestContext(w)

		m.VerifyNonceMiddleware(c)

		if len(c.Errors) > 0 {
			t.Errorf("verification failed with error: %v", c.Errors)
		}
	})

	t.Run("no check, difficulty 1", func(t *testing.T) {
		m, _ := New(&Middleware{
			Difficulty:  1,
			Check:       false,
			Secret:      "secret",
			ExtractData: func(c *gin.Context) (string, error) { return "data11111", nil },
			ExtractHash: func(c *gin.Context) (hash string, error error) {
				hash = "024b6380e07b20023e1b986b250b09bcfaa4551510ac4903a9b052e2b2cf9019"
				return
			},
			ExtractNonce: func(c *gin.Context) (nonce string, nonceChecksum string, error error) {
				nonce = "nonce"
				nonceChecksum = "0000"
				return
			},
		})
		w := httptest.NewRecorder()

		c, _ := gin.CreateTestContext(w)

		m.VerifyNonceMiddleware(c)

		if len(c.Errors) > 0 {
			t.Errorf("verification failed with error: %v", c.Errors)
		}
	})
	t.Run("push error to error stack", func(t *testing.T) {
		m, _ := New(&Middleware{
			Difficulty:  1,
			Check:       false,
			Secret:      "secret",
			ExtractData: func(c *gin.Context) (string, error) { return "data11111", nil },
			ExtractHash: func(c *gin.Context) (hash string, error error) {
				hash = "0000000000"
				return
			},
			ExtractNonce: func(c *gin.Context) (nonce string, nonceChecksum string, error error) {
				nonce = "nonce"
				nonceChecksum = "000000000000"
				return
			},
		})
		w := httptest.NewRecorder()

		c, _ := gin.CreateTestContext(w)

		m.VerifyNonceMiddleware(c)

		if len(c.Errors) == 0 {
			t.Error("no errors")
		}
	})

	t.Run("no nonce", func(t *testing.T) {
		m, _ := New(&Middleware{
			Difficulty:  1,
			Check:       false,
			Secret:      "secret",
			ExtractData: func(c *gin.Context) (string, error) { return "data11111", nil },
			ExtractHash: func(c *gin.Context) (hash string, error error) {
				hash = "000000000000"
				return
			},
			ExtractNonce: func(c *gin.Context) (nonce string, nonceChecksum string, error error) {
				nonce = ""
				nonceChecksum = "0000000000"
				return
			},
		})
		w := httptest.NewRecorder()

		c, _ := gin.CreateTestContext(w)

		m.VerifyNonceMiddleware(c)

		if expect := http.StatusBadRequest; w.Code != expect {
			t.Errorf("didn't return %v but %v", expect, w.Code)
		}
	})
	t.Run("no checksum when check true", func(t *testing.T) {
		m, _ := New(&Middleware{
			Difficulty:  1,
			Check:       true,
			Secret:      "secret",
			ExtractData: func(c *gin.Context) (string, error) { return "data11111", nil },
			ExtractHash: func(c *gin.Context) (hash string, error error) {
				hash = "not a valid hash"
				return
			},
			ExtractNonce: func(c *gin.Context) (nonce string, nonceChecksum string, error error) {
				nonce = "nonce"
				nonceChecksum = ""
				return
			},
		})
		w := httptest.NewRecorder()

		c, _ := gin.CreateTestContext(w)

		m.VerifyNonceMiddleware(c)
		if expect := http.StatusBadRequest; w.Code != expect {
			t.Errorf("didn't return %v but %v", expect, w.Code)
		}

	})
	t.Run("no hash", func(t *testing.T) {
		m, _ := New(&Middleware{
			Difficulty:  1,
			Check:       false,
			Secret:      "secret",
			ExtractData: func(c *gin.Context) (string, error) { return "data11111", nil },
			ExtractHash: func(c *gin.Context) (hash string, error error) {
				hash = ""
				return
			},
			ExtractNonce: func(c *gin.Context) (nonce string, nonceChecksum string, error error) {
				nonce = "nonce"
				nonceChecksum = "00000000"
				return
			},
		})
		w := httptest.NewRecorder()

		c, _ := gin.CreateTestContext(w)

		m.VerifyNonceMiddleware(c)

		if expect := http.StatusBadRequest; w.Code != expect {
			t.Errorf("didn't return %v but %v", expect, w.Code)
		}

	})

	t.Run("extract nonce or checksum error", func(t *testing.T) {
		m, _ := New(&Middleware{
			Difficulty:  1,
			Check:       false,
			Secret:      "secret",
			ExtractData: func(c *gin.Context) (string, error) { return "data11111", nil },
			ExtractHash: func(c *gin.Context) (hash string, error error) {
				hash = ""
				return
			},
			ExtractNonce: func(c *gin.Context) (nonce string, nonceChecksum string, error error) {
				return "", "", errors.New("")
			},
		})
		w := httptest.NewRecorder()

		c, _ := gin.CreateTestContext(w)

		m.VerifyNonceMiddleware(c)

		if expect := http.StatusInternalServerError; w.Code != expect {
			t.Errorf("didn't return %v but %v", expect, w.Code)
		}

	})

	t.Run("extract hash error", func(t *testing.T) {
		m, _ := New(&Middleware{
			Difficulty:  1,
			Check:       false,
			Secret:      "secret",
			ExtractData: func(c *gin.Context) (string, error) { return "data11111", nil },
			ExtractHash: func(c *gin.Context) (hash string, error error) {
				return "", errors.New("")
			},
			ExtractNonce: func(c *gin.Context) (nonce string, nonceChecksum string, error error) {
				nonce = "nonce"
				nonceChecksum = "0000000000"
				return
			},
		})
		w := httptest.NewRecorder()

		c, _ := gin.CreateTestContext(w)

		m.VerifyNonceMiddleware(c)

		if expect := http.StatusInternalServerError; w.Code != expect {
			t.Errorf("didn't return %v but %v", expect, w.Code)
		}

	})
	t.Run("extract data error", func(t *testing.T) {
		m, _ := New(&Middleware{
			Difficulty:  1,
			Check:       false,
			Secret:      "secret",
			ExtractData: func(c *gin.Context) (string, error) { return "", errors.New("") },
			ExtractHash: func(c *gin.Context) (hash string, error error) {
				return "", errors.New("")
			},
			ExtractNonce: func(c *gin.Context) (nonce string, nonceChecksum string, error error) {
				nonce = "nonce"
				nonceChecksum = "000000"
				return
			},
		})
		w := httptest.NewRecorder()

		c, _ := gin.CreateTestContext(w)

		m.VerifyNonceMiddleware(c)

		if expect := http.StatusInternalServerError; w.Code != expect {
			t.Errorf("didn't return %v but %v", expect, w.Code)
		}

	})

	t.Run("error aborts with 500 when error without abort", func(t *testing.T) {
		m, err := New(&Middleware{
			ExtractAll: func(c *gin.Context) (nonce string, nonceChecksum string, data string, hash string, err error) {
				err = errors.New("")
				return
			},
		})
		if err != nil {
			t.Errorf("error initializing middleware: %v", err)
			return
		}

		w := httptest.NewRecorder()

		c, _ := gin.CreateTestContext(w)

		m.VerifyNonceMiddleware(c)

		if expect := http.StatusInternalServerError; w.Code != expect {
			t.Errorf("didnt return expected code; Got: %v, Expected %v", w.Code, expect)
		}
	})

	t.Run("hash not hex", func(t *testing.T) {
		m, _ := New(&Middleware{
			Difficulty:  1,
			Check:       true,
			Secret:      "secret",
			ExtractData: func(c *gin.Context) (string, error) { return "data11111", nil },
			ExtractHash: func(c *gin.Context) (hash string, error error) {
				hash = "024b6380e07b20023e1b986db250b09bcfaa4551510ac4903a9b052e2b2cf9019"
				return
			},
			ExtractNonce: func(c *gin.Context) (nonce string, nonceChecksum string, error error) {
				nonce = "nonce"
				nonceChecksum = "5c420d7fedeb75e1309b1fe82f9c85d5552f1edfc11c72e7749330881166f18d"
				return
			},
		})
		w := httptest.NewRecorder()

		c, _ := gin.CreateTestContext(w)

		m.VerifyNonceMiddleware(c)

		if expect := http.StatusBadRequest; w.Code != expect {
			t.Errorf("didn't return expected status: Got: %v, Expected: %v", w.Code, expect)
		}
	})
	t.Run("checksum not hex", func(t *testing.T) {
		m, _ := New(&Middleware{
			Difficulty:  1,
			Check:       true,
			Secret:      "secret",
			ExtractData: func(c *gin.Context) (string, error) { return "data11111", nil },
			ExtractHash: func(c *gin.Context) (hash string, error error) {
				hash = "024b6380e07b20023e1b986b250b09bcfaa4551510ac4903a9b052e2b2cf9019"
				return
			},
			ExtractNonce: func(c *gin.Context) (nonce string, nonceChecksum string, error error) {
				nonce = "nonce"
				nonceChecksum = "5c420d7fedeb75e1309bd1fe82f9c85d5552f1edfc11c72e7749330881166f18d"
				return
			},
		})
		w := httptest.NewRecorder()

		c, _ := gin.CreateTestContext(w)

		m.VerifyNonceMiddleware(c)

		if expect := http.StatusBadRequest; w.Code != expect {
			t.Errorf("didn't return expected status: Got: %v, Expected: %v", w.Code, expect)
		}
	})

}
