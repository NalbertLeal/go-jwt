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
	expirationTime float64 = 30.0
)

func init() {
	go oldTokensGarbageCollector()
}

func SetExpirationTime(e float64) {
	expirationTime = e
}

func SetSecret(s string) {
	secret = []byte(s)
}

func GenerateNewToken(payload string) <-chan string {
	c := make(chan string)
	go func() {
		b64Payload := base64.RawURLEncoding.EncodeToString( []byte(payload) )
		token := createToken(b64Payload)
		insertTokenInMap(token)
		c <- token
	}()
	return c
}

func ValidateToken(token string) <-chan bool {
	c := make(chan bool)
	go func() {
		tokensRWMutex.RLock()
		defer tokensRWMutex.RUnlock()
		
		lastTimeUsed, ok := tokens[token]
		isTokenExpired := verifyTokenExpirated(lastTimeUsed)
		isValid := ok && !isTokenExpired

		c <- isValid
	}()
	return c
}

func createToken(b64Payload string) string {
	unsignedToken := defaultTokenHeader + b64Payload
	signature := createSignature(unsignedToken)
	return unsignedToken + "." + signature
}

func createSignature(unsignedToken string) string {
	data := []byte(unsignedToken)

	hash := hmac.New(sha256.New, secret)
	hash.Write( data )
	signature := base64.RawURLEncoding.EncodeToString( hash.Sum(nil) )
	return signature
}

func insertTokenInMap(token string) {
	tokensRWMutex.Lock()
	defer tokensRWMutex.Unlock()
	tokens[token] = time.Now()
}

func oldTokensGarbageCollector() {
	for {
		time.Sleep(time.Minute * 5)

		tokensRWMutex.Lock()
		for token, lastTimeUsed := range tokens {
			isTokenExpired := verifyTokenExpirated(lastTimeUsed)
			if !isTokenExpired {
				deleteOldToken(token)
			}
		}
		tokensRWMutex.Unlock()
	}
}

func verifyTokenExpirated(lastTimeUsed time.Time) bool {
	duration := time.Since(lastTimeUsed)
	return duration.Minutes() > expirationTime
}

func deleteOldToken(token string) {
	//* safe to modify the map because function "oldTokensCollector" already
	//* have a lock
	delete(tokens, token)
}