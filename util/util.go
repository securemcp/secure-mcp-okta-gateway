package util

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"regexp"
)

func RandString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func S256(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func IsValidCodeChallengeOrVerifier(s string) bool {
	if len(s) < 43 || len(s) > 128 {
		return false
	}
	matched, _ := regexp.MatchString(`^[A-Za-z0-9\-\._~]{43,128}$`, s)
	return matched
}
