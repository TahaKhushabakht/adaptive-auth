package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
)

type apiServer struct {
	db *sql.DB
}

func (s *apiServer) registerHandler(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("registered: " + req.Email))
}