package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"sync"
	"time"
)

const (
	defaultTokenHeader = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
)

var (
	tokensRWMutex sync.RWMutex
	tokens map[string]time.Time = map[string]time.Time{}
	secret []byte = []byte("@-use-your-own-secret-@")
)

func init() {
	go oldTokensCollector()
}

func SetSecret(s string) {
	secret = []byte(s)
}

func GenerateNewToken(payload string) <-chan string {
	c := make(chan string)
	go func() {
		b64Payload := base64.RawURLEncoding.EncodeToString( []byte(payload) )
		
		unsignedToken := defaultTokenHeader + b64Payload
		signature := createSignature(unsignedToken)
		token := unsignedToken + "." + signature
		
		tokensRWMutex.Lock()
		defer tokensRWMutex.Unlock()
		tokens[token] = time.Now()

		c <- token
	}()
	return c
}

func ValidateToken(token string) <-chan bool {
	c := make(chan bool)
	go func() {
		tokensRWMutex.RLock()
		defer tokensRWMutex.RUnlock()
		_, ok := tokens[token]
		c <- ok
	}()
	return c
}

// Return:
//   HMACSHA256(base64UrlEncode(header)+"."+base64UrlEncode(payload),your-256-bit-secret)
func createSignature(unsignedToken string) string {
	data := []byte(unsignedToken)

	hash := hmac.New(sha256.New, secret)
	hash.Write( data )
	signature := base64.RawURLEncoding.EncodeToString( hash.Sum(nil) )
	return signature
}

func oldTokensCollector() {
	for {
		time.Sleep(time.Minute * 5)

		tokensRWMutex.Lock()
		for token, lastTimeUsed := range tokens {
			duration := time.Since(lastTimeUsed)
			if duration.Minutes() > 30 {
				deleteOldToken(token)
			}
		}
		tokensRWMutex.Unlock()
	}
}

func deleteOldToken(token string) {
	//* safe to modify the map because function "oldTokensCollector" already
	//* have a lock
	delete(tokens, token)
}