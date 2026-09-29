package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

var ErrNotFound = errors.New("not found")

type Store struct {
	db *sql.DB
}

func (s *Store) UserEmail(ctx context.Context, id int64) (string, error) {
	var email string
	err := s.db.QueryRowContext(ctx, "SELECT email FROM users WHERE id = $1", id).Scan(&email)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("looking up user %d: %w", id, err)
	}
	return email, nil
}
