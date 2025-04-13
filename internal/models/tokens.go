package models

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/jmoiron/sqlx"
)

type Token struct {
	ID        int       `db:"id"`
	UserID    int       `db:"user_id"`
	Token     string    `db:"token"`
	TokenType string    `db:"token_type"`
	CreatedAt time.Time `db:"created_at"`
	ExpiresAt time.Time `db:"expires_at"`
}

type TokenModel struct {
	DB *sqlx.DB
}

const (
	ScopeActivation     = "activation"
	ScopePasswordReset = "password-reset"
)

func (m TokenModel) New(userID int, ttl time.Duration, scope string) (*Token, error) {
	token, err := generateToken(userID, ttl, scope)
	if err != nil {
		return nil, err
	}

	err = m.Insert(token)
	return token, err
}

func (m TokenModel) Insert(token *Token) error {
	query := `
		INSERT INTO tokens (user_id, token, token_type, expires_at)
		VALUES (:user_id, :token, :token_type, :expires_at)
	`

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := m.DB.NamedExecContext(ctx, query, token)
	return err
}

func (m TokenModel) DeleteAllForUser(scope string, userID int) error {
	query := `
		DELETE FROM tokens
		WHERE token_type = ? AND user_id = ?
	`

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := m.DB.ExecContext(ctx, query, scope, userID)
	return err
}

func generateToken(userID int, ttl time.Duration, scope string) (*Token, error) {
	token := &Token{
		UserID:    userID,
		TokenType: scope,
		ExpiresAt: time.Now().Add(ttl),
	}

	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return nil, err
	}

	token.Token = base64.StdEncoding.EncodeToString(randomBytes)
	return token, nil
}