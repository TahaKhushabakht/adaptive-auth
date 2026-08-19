package main

import (
	"database/sql"
	"time"

	_ "modernc.org/sqlite"
)

const createUsersTable = `
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	totp_secret    TEXT,
	totp_confirmed INTEGER NOT NULL DEFAULT 0
	)`

const createSessionsTable = `
CREATE TABLE IF NOT EXISTS sessions (
	token_hash TEXT PRIMARY KEY,
	user_id TEXT NOT NULL,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	expires_at TIMESTAMP NOT NULL,
	FOREIGN KEY (user_id) REFERENCES users(id)
	)`

const createLoginEventsTable = `
CREATE TABLE IF NOT EXISTS login_events (
	id TEXT PRIMARY KEY,
	user_id TEXT,
	email TEXT NOT NULL,
	success INTEGER NOT NULL,
	ip_address TEXT NOT NULL,
	user_agent TEXT,
	device_id TEXT NOT NULL,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	country   TEXT,
	city      TEXT,
	latitude  REAL,
	longitude REAL,
	event_type TEXT NOT NULL DEFAULT 'login',
	risk_score INTEGER,
	decision   TEXT,
	FOREIGN KEY (user_id) REFERENCES users(id)
	)`

const createLoginEventsIndexes = `
	CREATE INDEX IF NOT EXISTS idx_login_events_user ON login_events(user_id, event_type, created_at);
	CREATE INDEX IF NOT EXISTS idx_login_events_ip   ON login_events(ip_address, event_type, created_at);`

const createLoginChallengesTable = `
CREATE TABLE IF NOT EXISTS login_challenges (
	challenge_hash TEXT PRIMARY KEY,
	user_id TEXT NOT NULL,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	expires_at TIMESTAMP NOT NULL,
	attempts INTEGER NOT NULL DEFAULT 0,
	FOREIGN KEY (user_id) REFERENCES users(id)
	)`

func openDatabase(path string) (*sql.DB, error) {
	dsn := path + "?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}
	if _, err := db.Exec(createUsersTable); err != nil {
		return nil, err
	}
	if _, err := db.Exec(createSessionsTable); err != nil {
		return nil, err
	}
	if _, err := db.Exec(createLoginEventsTable); err != nil {
		return nil, err
	}
	if _, err := db.Exec(createLoginEventsIndexes); err != nil {
		return nil, err
	}
	if _, err := db.Exec(createLoginChallengesTable); err != nil {
		return nil, err
	}
	return db, nil
}

func purgeExpiredSessions(db *sql.DB) (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	result, err := db.Exec("DELETE FROM sessions WHERE expires_at < ?", now)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
