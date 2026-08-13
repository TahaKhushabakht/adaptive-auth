package main

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

