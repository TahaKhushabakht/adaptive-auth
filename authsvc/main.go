package main

import (
	"log"
	"net/http"
	"time"
)

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		log.Printf("Received request: %s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
		log.Printf("Request completed in %f seconds", time.Since(start).Seconds())

	})
}

func main() {

	db, err := openDatabase("adaptive_auth.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()
	dummy, err := hashPassword("a-password-nobody-will-ever-use")
	if err != nil {
		log.Fatalf("Failed to hash dummy password: %v", err)
	}
	srv := &apiServer{db: db, dummyHash: dummy}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthzHandler)
	mux.HandleFunc("POST /register", srv.registerHandler)
	mux.HandleFunc("POST /login", srv.loginHandler)
	mux.Handle("GET /me", srv.requireAuth(http.HandlerFunc(srv.meHandler)))
	if err := http.ListenAndServe(":8081", withLogging(mux)); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
