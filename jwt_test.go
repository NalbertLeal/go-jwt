package jwt

import "testing"

func TestGenerateNewToken(t *testing.T) {
	payload := "{\"user\":\"NalberLeal\"}"
	expectedToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiTmFsYmVyTGVhbCJ9.VKPJCZFkw17AeXbnFnIOAMaBUlTO7yYCG2_pbVcJW_4"

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