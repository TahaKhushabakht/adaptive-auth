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
	"github.com/oschwald/geoip2-golang"
)

type apiServer struct {
	db        *sql.DB
	dummyHash string
	geoDB     *geoip2.Reader
}

func (s *apiServer) registerHandler(w http.ResponseWriter, r *http.Request) {
	var req registerRequest

	ip, err := clientIP(r)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	deviceID, err := getOrSetDeviceID(w, r)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	id := uuid.NewString()
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	if req.Email == "" || req.Password == "" {
		http.Error(w, "Email and password are required", http.StatusBadRequest)
		return
	}
	if len(req.Password) < 8 || len(req.Password) > 128 {
		http.Error(w, "Password must be between 8 and 128 characters", http.StatusBadRequest)
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
			s.recordAuthEvent("register", "", req.Email, false, ip, r.UserAgent(), deviceID)
			return
		}
		http.Error(w, "Failed to register user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("registered: " + req.Email))
	s.recordAuthEvent("register", id, req.Email, true, ip, r.UserAgent(), deviceID)
}

func (s *apiServer) loginHandler(w http.ResponseWriter, r *http.Request) {
	var req loginRequest

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	ip, err := clientIP(r)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	deviceID, err := getOrSetDeviceID(w, r)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	if req.Email == "" || req.Password == "" {
		http.Error(w, "Email and password are required", http.StatusBadRequest)
		return
	}

	if len(req.Password) > 128 {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	var id, storedHash string
	err = s.db.QueryRow("SELECT id, password_hash FROM users WHERE email = ?",
		req.Email).Scan(&id, &storedHash)

	if errors.Is(err, sql.ErrNoRows) {

		_, _ = verifyPassword(s.dummyHash, req.Password)
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		s.recordAuthEvent("login", "", req.Email, false, ip, r.UserAgent(), deviceID)
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
		s.recordAuthEvent("login", id, req.Email, false, ip, r.UserAgent(), deviceID)
		return
	}

	token, err := generateRandomToken()
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
	s.recordAuthEvent("login", id, req.Email, true, ip, r.UserAgent(), deviceID)
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
		ip, err := clientIP(r)
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

func (s *apiServer) recordAuthEvent(eventType, userID, email string, success bool, ip, userAgent string, deviceID string) {
	var userIDArg any = nil
	if userID != "" {
		userIDArg = userID
	}

	var country, city string
	var lat, lon float64

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		log.Printf("could not parse IP for geo lookup: %q", ip)
	} else if record, err := s.geoDB.City(parsedIP); err != nil {
		log.Printf("geo lookup failed for %s: %v", ip, err)
	} else {
		country = record.Country.Names["en"]
		city = record.City.Names["en"]
		lat = record.Location.Latitude
		lon = record.Location.Longitude
	}
	var countryArg, cityArg any = nil, nil
	if country != "" {
		countryArg = country
	}
	if city != "" {
		cityArg = city
	}

	var latArg, lonArg any = nil, nil
	if lat != 0 || lon != 0 {
		latArg = lat
		lonArg = lon
	}

	_, err := s.db.Exec(
		"INSERT INTO login_events (id, user_id, email, success, ip_address, user_agent, device_id, country, city, latitude, longitude, event_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		uuid.NewString(), userIDArg, email, success, ip, userAgent, deviceID, countryArg, cityArg, latArg, lonArg, eventType,
	)
	if err != nil {
		log.Printf("failed to record login event %v", err)
	}
}

func getOrSetDeviceID(w http.ResponseWriter, r *http.Request) (string, error) {
	if cookie, err := r.Cookie("device_id"); err == nil {
		return cookie.Value, nil
	}
	deviceID, err := generateRandomToken()
	if err != nil {
		return "", err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "device_id",
		Value:    deviceID,
		Expires:  time.Now().Add(365 * 24 * time.Hour),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})
	return deviceID, nil
}
func (s *apiServer) logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}

	_, err = s.db.Exec("DELETE FROM sessions WHERE token_hash = ?", hashToken(cookie.Value))
	if err != nil {
		http.Error(w, "failed to log out", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("logged out"))
}
