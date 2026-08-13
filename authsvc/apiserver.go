package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

type apiServer struct {
	db *sql.DB
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
	if err!= nil{
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
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}
	if err != nil {
		http.Error(w, "Failed to query user", http.StatusInternalServerError)
		return
	}


	ok, err := verifyPassword(storedHash, req.Password)

	
	if  err != nil {
		log.Printf("verify failed for user %s: %v", id, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("logged in: " + req.Email))
}
