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
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (user_id) REFERENCES users(id)
	)`

func openDatabase(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
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

	return db, nil
}
