package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

type apiServer struct {
	db        *sql.DB
	dummyHash string
}

func (s *apiServer) registerHandler(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	id := uuid.NewString()
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}
	if req.Email == "" || req.Password == "" {
		http.Error(w, "Email and password are required", http.StatusBadRequest)
		return
	}
	hashed, err := hashPassword(req.Password)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}
	_, err = s.db.Exec("INSERT INTO users (id, email, password_hash) VALUES (?, ?, ?)", id, req.Email, hashed)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			http.Error(w, "Email already registered", http.StatusConflict)
			return
		}
		http.Error(w, "Failed to register user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("registered: " + req.Email))
}

func (s *apiServer) loginHandler(w http.ResponseWriter, r *http.Request) {
	var req loginRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}
	if req.Email == "" || req.Password == "" {
		http.Error(w, "Email and password are required", http.StatusBadRequest)
		return
	}

	var id, storedHash string
	err := s.db.QueryRow("SELECT id, password_hash FROM users WHERE email = ?",
		req.Email).Scan(&id, &storedHash)

	if errors.Is(err, sql.ErrNoRows) {

		_, _ = verifyPassword(s.dummyHash, req.Password)

		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}
	if err != nil {
		http.Error(w, "Failed to query user", http.StatusInternalServerError)
		return
	}

	ok, err := verifyPassword(storedHash, req.Password)

	if err != nil {
		log.Printf("verify failed for user %s: %v", id, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	token, err := generateSessionToken()
	if err != nil {
		http.Error(w, "Failed to generate session token", http.StatusInternalServerError)
		return
	}
	expiresAt := time.Now().Add(24 * time.Hour)
	expiresAtStr := expiresAt.UTC().Format(time.RFC3339)

	_, err = s.db.Exec(
		"INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
		hashToken(token), id, expiresAtStr)
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    token,
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("logged in: " + req.Email))
}

type contextKey string

const userIDKey contextKey = "userID"

func (s *apiServer) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_token")
		if err != nil {
			http.Error(w, "not authenticated", http.StatusUnauthorized)
			return
		}
		var userID, expiresAtStr string
		err = s.db.QueryRow("SELECT user_id, expires_at FROM sessions WHERE token_hash = ?",
			hashToken(cookie.Value)).Scan(&userID, &expiresAtStr)
		if err != nil {
			http.Error(w, "not authenticated", http.StatusUnauthorized)
			return
		}

		expiresAt, err := time.Parse(time.RFC3339, expiresAtStr)
		if err != nil || time.Now().After(expiresAt) {
			http.Error(w, "session expired", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), userIDKey, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *apiServer) meHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(userIDKey).(string)
	if !ok || userID == "" {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	w.Write([]byte("you are: " + userID))
}

func rateLimit(limiter *ipRateLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		l := limiter.getLimiter(ip)
		if !l.Allow() {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
