package main

import (
	"golang.org/x/time/rate"
	"log"
	"net/http"
	"time"

	"github.com/oschwald/geoip2-golang"
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
	n, err := purgeExpiredSessions(db)
	if err != nil {
		log.Printf("failed to purge expired sessions: %v", err)
	} else {
		log.Printf("purged %d expired sessions", n)
	}
	defer db.Close()
	geoDB, err := geoip2.Open("geoip/GeoLite2-City.mmdb")
	if err != nil {
		log.Fatalf("failed to open GeoIP database: %v", err)
	}
	defer geoDB.Close()
	dummy, err := hashPassword("a-password-nobody-will-ever-use")
	if err != nil {
		log.Fatalf("Failed to hash dummy password: %v", err)
	}
	loginLimiter := newIPRateLimiter(rate.Limit(0.1), 5)
	registrationLimiter := newIPRateLimiter(rate.Limit(1), 5)
	srv := &apiServer{db: db, dummyHash: dummy, geoDB: geoDB}
	mux := http.NewServeMux()
	mux.Handle("/healthz", http.HandlerFunc(healthzHandler))
	mux.Handle("POST /register", rateLimit(registrationLimiter, http.HandlerFunc(srv.registerHandler)))
	mux.Handle("POST /login", rateLimit(loginLimiter, http.HandlerFunc(srv.loginHandler)))
	mux.Handle("GET /me", srv.requireAuth(http.HandlerFunc(srv.meHandler)))
	mux.Handle("POST /logout", srv.requireAuth(http.HandlerFunc(srv.logoutHandler)))

	if err := http.ListenAndServe(":8081", withLogging(mux)); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
