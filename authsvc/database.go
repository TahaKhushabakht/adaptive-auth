package main

import (
	"database/sql"

	_ "modernc.org/sqlite"
)

const createUsersTable = `
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
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
	FOREIGN KEY (user_id) REFERENCES users(id)
	)`

const createLoginEventsIndexes = `
	CREATE INDEX IF NOT EXISTS idx_login_events_user ON login_events(user_id, event_type, created_at);
	CREATE INDEX IF NOT EXISTS idx_login_events_ip   ON login_events(ip_address, event_type, created_at);
	`

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
	return db, nil
}
