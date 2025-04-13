package models

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"time"

	"github.com/jmoiron/sqlx"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID           int       `db:"id"`
	Name         string    `db:"name"`
	Email        string    `db:"email"`
	PasswordHash []byte    `db:"password_hash"`
	Role         string    `db:"role"`
	Activated    bool      `db:"activated"`
	CreatedAt    time.Time `db:"created_at"`
	UpdatedAt    time.Time `db:"updated_at"`
}

type UserModel struct {
	DB *sqlx.DB
}

func (m UserModel) Insert(user *User) error {
	query := `
		INSERT INTO users (name, email, password_hash, role, activated)
		VALUES (:name, :email, :password_hash, :role, :activated)
		RETURNING id, created_at, updated_at
	`

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	stmt, err := m.DB.PrepareNamedContext(ctx, query)
	if err != nil {
		return err
	}
	defer stmt.Close()

	err = stmt.GetContext(ctx, user, user)
	if err != nil {
		// Check for duplicate email error (SQLite specific)
		if err.Error() == "UNIQUE constraint failed: users.email" {
			return ErrDuplicateEmail
		}
		return err
	}

	return nil
}

func (m UserModel) GetByEmail(email string) (*User, error) {
	query := `
		SELECT id, name, email, password_hash, role, activated, created_at, updated_at
		FROM users
		WHERE email = ?
	`

	var user User

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := m.DB.GetContext(ctx, &user, query, email)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil, ErrRecordNotFound
		default:
			return nil, err
		}
	}

	return &user, nil
}

func (m UserModel) Exists(id int) (bool, error) {
	var exists bool

	query := `
		SELECT EXISTS(SELECT true FROM users WHERE id = ?)
	`

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := m.DB.QueryRowContext(ctx, query, id).Scan(&exists)
	return exists, err
}

func (m UserModel) GetForToken(tokenScope, tokenPlainText string) (*User, error) {
	// This method will be used for both activation and password reset tokens
	query := `
		SELECT users.id, users.name, users.email, users.password_hash, users.role, users.activated, users.created_at, users.updated_at
		FROM users
		INNER JOIN tokens
		ON users.id = tokens.user_id
		WHERE tokens.token = ?
		AND tokens.token_type = ?
		AND tokens.expires_at > ?
	`

	// Hash the plaintext token
	tokenHash := sha256.Sum256([]byte(tokenPlainText))

	var user User

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := m.DB.GetContext(ctx, &user, query, tokenHash[:], tokenScope, time.Now())
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil, ErrRecordNotFound
		default:
			return nil, err
		}
	}

	return &user, nil
}

func (m UserModel) GetById(id int) (*User, error) {
	query := `
		SELECT id, name, email, password_hash, role, activated, created_at, updated_at
		FROM users
		WHERE id = ?
	`

	var user User

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := m.DB.GetContext(ctx, &user, query, id)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil, ErrRecordNotFound
		default:
			return nil, err
		}
	}

	return &user, nil
}

func (m UserModel) Update(user *User) error {
	query := `
		UPDATE users
		SET name = :name, email = :email, password_hash = :password_hash,
		    role = :role, activated = :activated, updated_at = CURRENT_TIMESTAMP
		WHERE id = :id
	`

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := m.DB.NamedExecContext(ctx, query, user)
	return err
}

func (m UserModel) PasswordMatches(user *User, plaintextPassword string) (bool, error) {
	err := bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(plaintextPassword))
	if err != nil {
		switch {
		case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
			return false, nil
		default:
			return false, err
		}
	}

	return true, nil
}