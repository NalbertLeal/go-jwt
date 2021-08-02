package jwt

import (
	"testing"
	"time"
)

const (
	payload       = "{\"user\":\"NalberLeal\"}"
	expectedToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiTmFsYmVyTGVhbCJ9.VKPJCZFkw17AeXbnFnIOAMaBUlTO7yYCG2_pbVcJW_4"
)

func TestGenerateNewToken(t *testing.T) {
	token := <-GenerateNewToken(payload)
	if token != expectedToken {
		t.Error("The generated token is wrong")
	}
}

func TestValidateToken(t *testing.T) {
	payload := "{\"user\":\"NalberLeal\"}"

	token := <-GenerateNewToken(payload)
	isValid := <-ValidateToken(token)

	if !isValid {
		t.Error("Token should be valid, but was returned as invalid")
	}
}

func TestVerifyTokenExpirated(t *testing.T) {
	token := <-GenerateNewToken(payload)
	tokenTime := tokens[token]
	isExpirated := verifyTokenExpirated(tokenTime)
	if isExpirated {
		t.Error("Token is expirated but should't")
	}
}

func TestAutomaticTokenDeletion(t *testing.T) {
	//* Expiration time setup to 600 miliseconds
	SetExpirationTime(0.01)

	token := <-GenerateNewToken(payload)
	time.Sleep(time.Second * 1)
	isValid := <-ValidateToken(token)
	if isValid {
		t.Error("The token should't be valid")
	}
}
