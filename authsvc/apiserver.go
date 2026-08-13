package main

import (
	"database/sql"
	"encoding/json"
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