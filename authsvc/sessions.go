package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

func generateSessionToken() (string, error) {
	sessionToken := make([]byte, 32)
	if _, err := rand.Read(sessionToken); err != nil {
		return "", fmt.Errorf("failed to generate session token: %v", err)
	}
	b64SessionToken := base64.RawURLEncoding.EncodeToString(sessionToken)
	return b64SessionToken, nil
}

func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
