package models

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jmoiron/sqlx"
)

type Post struct {
	ID        int       `db:"id"`
	UserID    int       `db:"user_id"`
	Title     string    `db:"title"`
	Content   string    `db:"content"`
	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

type PostModel struct {
	DB *sqlx.DB
}

func (m PostModel) Insert(post *Post) error {
	query := `
		INSERT INTO posts (user_id, title, content)
		VALUES (:user_id, :title, :content)
		RETURNING id, created_at, updated_at
	`

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	stmt, err := m.DB.PrepareNamedContext(ctx, query)
	if err != nil {
		return err
	}
	defer stmt.Close()

	return stmt.GetContext(ctx, post, post)
}

func (m PostModel) Get(id int) (*Post, error) {
	query := `
		SELECT id, user_id, title, content, created_at, updated_at
		FROM posts
		WHERE id = ?
	`

	var post Post

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := m.DB.GetContext(ctx, &post, query, id)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil, ErrRecordNotFound
		default:
			return nil, err
		}
	}

	return &post, nil
}

func (m PostModel) Latest() ([]*Post, error) {
	query := `
		SELECT id, user_id, title, content, created_at, updated_at
		FROM posts
		ORDER BY created_at DESC
		LIMIT 10
	`

	var posts []*Post

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := m.DB.SelectContext(ctx, &posts, query)
	if err != nil {
		return nil, err
	}

	return posts, nil
}

func (m PostModel) Update(post *Post) error {
	query := `
		UPDATE posts
		SET title = :title, content = :content, updated_at = CURRENT_TIMESTAMP
		WHERE id = :id
	`

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := m.DB.NamedExecContext(ctx, query, post)
	return err
}

func (m PostModel) Delete(id int) error {
	query := `
		DELETE FROM posts
		WHERE id = ?
	`

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	result, err := m.DB.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return ErrRecordNotFound
	}

	return nil
}

func (m PostModel) GetForUser(userID int) ([]*Post, error) {
	query := `
		SELECT id, user_id, title, content, created_at, updated_at
		FROM posts
		WHERE user_id = ?
		ORDER BY created_at DESC
	`

	var posts []*Post

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := m.DB.SelectContext(ctx, &posts, query, userID)
	if err != nil {
		return nil, err
	}

	return posts, nil
}