package store

import (
	"database/sql"
	"errors"
)

var ErrNotFound = errors.New("not found")

type Store struct {
	db *sql.DB
}

func (s *Store) UserEmail(id int64) (string, error) {
	var email string
	err := s.db.QueryRow("SELECT email FROM users WHERE id = $1", id).Scan(&email)
	if err == sql.ErrNoRows {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	return email, nil
}
