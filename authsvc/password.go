package main

import (
	"encoding/base64"
	"fmt"
	"strings"
	"crypto/rand"
	"crypto/subtle"

	"golang.org/x/crypto/argon2"
)

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %v", err)
	}
	hash := argon2.IDKey([]byte(password), salt, 3, 65536, 2, 32)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	encoded := fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=2$%s$%s", b64Salt, b64Hash) 
	return encoded, nil
}

func verifyPassword(encodedHash, password string) (bool, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return false, fmt.Errorf("invalid encoded hash format")
	}
	b64Salt := parts[4]
	b64Hash := parts[5]

	salt, err := base64.RawStdEncoding.DecodeString(b64Salt)
	if err != nil {
		return false, fmt.Errorf("failed to decode salt: %v", err)
	}
	expectedHash, err := base64.RawStdEncoding.DecodeString(b64Hash)
	if err != nil {
		return false, fmt.Errorf("failed to decode hash: %v", err)
	}

	hash := argon2.IDKey([]byte(password), salt, 3, 65536, 2, uint32(len(expectedHash)))
	if subtle.ConstantTimeCompare(hash, expectedHash) == 1 {
		return true, nil
	}
	return false, nil
}
