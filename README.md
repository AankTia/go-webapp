# Building a Web Application with Go and SQLite

Here's a comprehensive step-by-step guide to building a web application with all the requested features.

## Step 1: Project Setup

```bash
# Create project directory
mkdir go-webapp
cd go-webapp

# Initialize Go module
go mod init github.com/yourusername/go-webapp

# Create directory structure
mkdir -p \
  cmd/web \
  internal/models \
  internal/forms \
  internal/mailer \
  ui/html \
  ui/static/css \
  ui/static/js \
  ui/static/images \
  migrations
```

## Step 2: Install Dependencies

```bash
go get \
  github.com/alexedwards/scs/v2 \
  github.com/go-chi/chi/v5 \
  github.com/go-chi/cors \
  github.com/go-playground/validator/v10 \
  github.com/jmoiron/sqlx \
  github.com/mattn/go-sqlite3 \
  golang.org/x/crypto/bcrypt \
  github.com/pressly/goose/v3 \
  github.com/justinas/nosurf \
  github.com/cespare/xxhash/v2 \
  github.com/dgraph-io/badger/v3 \
  github.com/go-mail/mail/v2 \
  github.com/rs/zerolog \
  github.com/rs/zerolog/hlog
```

## Step 3: Database Setup (SQLite)

Create `internal/models/db.go`:

```go
package models

import (
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
	"github.com/jmoiron/sqlx"
)

func InitDB(dataSourceName string) (*sqlx.DB, error) {
	db, err := sqlx.Open("sqlite3", dataSourceName)
	if err != nil {
		return nil, err
	}
	
	if err = db.Ping(); err != nil {
		return nil, err
	}
	
	return db, nil
}
```

## Step 4: Create Database Schema

Create `migrations/00001_init_schema.sql`:

```sql
-- Users table
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    activated BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Tokens table for email verification and password resets
CREATE TABLE IF NOT EXISTS tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT NOT NULL,
    token_type TEXT NOT NULL, -- 'verification' or 'password_reset'
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Example resource table
CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);
```

## Step 5: Application Structure

Create `cmd/web/main.go`:

```go
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yourusername/go-webapp/internal/models"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
)

type application struct {
	config config
	logger *zerolog.Logger
	models models.Models
	mailer Mailer
}

type config struct {
	port int
	env  string
	db   struct {
		dsn string
	}
	smtp struct {
		host     string
		port     int
		username string
		password string
		sender   string
	}
	secretKey string
}

func main() {
	var cfg config

	flag.IntVar(&cfg.port, "port", 4000, "API server port")
	flag.StringVar(&cfg.env, "env", "development", "Environment (development|staging|production)")
	flag.StringVar(&cfg.db.dsn, "db-dsn", "webapp.db", "SQLite DSN")
	flag.StringVar(&cfg.smtp.host, "smtp-host", "smtp.mailtrap.io", "SMTP host")
	flag.IntVar(&cfg.smtp.port, "smtp-port", 587, "SMTP port")
	flag.StringVar(&cfg.smtp.username, "smtp-username", "", "SMTP username")
	flag.StringVar(&cfg.smtp.password, "smtp-password", "", "SMTP password")
	flag.StringVar(&cfg.smtp.sender, "smtp-sender", "Go WebApp <no-reply@example.com>", "SMTP sender")
	flag.StringVar(&cfg.secretKey, "secret-key", "secret-key", "Secret key")
	flag.Parse()

	// Initialize logger
	logger := zerolog.New(os.Stdout).With().Timestamp().Logger()

	// Connect to database
	db, err := models.InitDB(cfg.db.dsn)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to connect to database")
	}
	defer db.Close()

	// Run migrations
	err = runMigrations(cfg.db.dsn)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to run migrations")
	}

	app := &application{
		config: cfg,
		logger: &logger,
		models: models.NewModels(db),
		mailer: NewMailer(cfg.smtp.host, cfg.smtp.port, cfg.smtp.username, cfg.smtp.password, cfg.smtp.sender),
	}

	// Server configuration
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.port),
		Handler:      app.routes(),
		IdleTimeout:  time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	// Graceful shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal().Err(err).Msg("failed to start server")
		}
	}()

	logger.Info().Msgf("starting %s server on %s", cfg.env, srv.Addr)

	<-done
	logger.Info().Msg("server stopped")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Fatal().Err(err).Msg("server shutdown failed")
	}

	logger.Info().Msg("server exited properly")
}

func runMigrations(dsn string) error {
	// Implementation for running migrations using goose
	return nil
}
```

## Step 6: Implement Models

Create `internal/models/models.go`:

```go
package models

import "github.com/jmoiron/sqlx"

type Models struct {
	Users  UserModel
	Tokens TokenModel
	Posts  PostModel
}

func NewModels(db *sqlx.DB) Models {
	return Models{
		Users:  UserModel{DB: db},
		Tokens: TokenModel{DB: db},
		Posts:  PostModel{DB: db},
	}
}
```

Create `internal/models/users.go`:

```go
package models

import (
	"context"
	"database/sql"
	"errors"
	"time"

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

	return stmt.GetContext(ctx, user, user)
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

func (m UserModel) GetByID(id int) (*User, error) {
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
```

## Step 7: Implement Authentication

Create `cmd/web/auth.go`:

```go
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yourusername/go-webapp/internal/models"
	"github.com/alexedwards/scs/v2"
	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"
)

func (app *application) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session := app.sessionManager.GetString(r.Context(), "authenticatedUserID")
		if session == "" {
			next.ServeHTTP(w, r)
			return
		}

		id, err := strconv.Atoi(session)
		if err != nil {
			app.serverError(w, r, err)
			return
		}

		exists, err := app.models.Users.Exists(id)
		if err != nil {
			app.serverError(w, r, err)
			return
		}

		if exists {
			ctx := context.WithValue(r.Context(), isAuthenticatedContextKey, true)
			r = r.WithContext(ctx)
		}

		next.ServeHTTP(w, r)
	})
}

func (app *application) requireAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !app.isAuthenticated(r) {
			http.Redirect(w, r, "/user/login", http.StatusSeeOther)
			return
		}

		w.Header().Add("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (app *application) requireRole(role string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !app.isAuthenticated(r) {
			http.Redirect(w, r, "/user/login", http.StatusSeeOther)
			return
		}

		userID := app.sessionManager.GetInt(r.Context(), "authenticatedUserID")
		user, err := app.models.Users.GetByID(userID)
		if err != nil {
			app.serverError(w, r, err)
			return
		}

		if user.Role != role {
			app.clientError(w, http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (app *application) createAuthenticationToken(userID int) (string, error) {
	token := make([]byte, 32)
	_, err := rand.Read(token)
	if err != nil {
		return "", err
	}

	tokenString := base64.StdEncoding.EncodeToString(token)

	err = app.models.Tokens.Insert(userID, tokenString, 24*time.Hour)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (app *application) loginUser(w http.ResponseWriter, r *http.Request, id int) error {
	err := app.sessionManager.RenewToken(r.Context())
	if err != nil {
		return err
	}

	app.sessionManager.Put(r.Context(), "authenticatedUserID", id)
	return nil
}

func (app *application) logoutUser(w http.ResponseWriter, r *http.Request) error {
	err := app.sessionManager.RenewToken(r.Context())
	if err != nil {
		return err
	}

	app.sessionManager.Remove(r.Context(), "authenticatedUserID")
	app.sessionManager.Put(r.Context(), "flash", "You've been logged out successfully!")
	return nil
}

func (app *application) isAuthenticated(r *http.Request) bool {
	isAuthenticated, ok := r.Context().Value(isAuthenticatedContextKey).(bool)
	if !ok {
		return false
	}
	return isAuthenticated
}
```

## Step 8: Implement Email Verification and Password Reset

Create `cmd/web/mailer.go`:

```go
package main

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"time"

	"github.com/go-mail/mail/v2"
)

type Mailer struct {
	dialer *mail.Dialer
	sender string
}

func NewMailer(host string, port int, username, password, sender string) Mailer {
	dialer := mail.NewDialer(host, port, username, password)
	dialer.Timeout = 5 * time.Second

	return Mailer{
		dialer: dialer,
		sender: sender,
	}
}

func (m Mailer) Send(recipient, templateFile string, data interface{}) error {
	tmpl, err := template.New("email").ParseFS(emailTemplates, "templates/"+templateFile)
	if err != nil {
		return err
	}

	subject := new(bytes.Buffer)
	err = tmpl.ExecuteTemplate(subject, "subject", data)
	if err != nil {
		return err
	}

	plainBody := new(bytes.Buffer)
	err = tmpl.ExecuteTemplate(plainBody, "plainBody", data)
	if err != nil {
		return err
	}

	htmlBody := new(bytes.Buffer)
	err = tmpl.ExecuteTemplate(htmlBody, "htmlBody", data)
	if err != nil {
		return err
	}

	msg := mail.NewMessage()
	msg.SetHeader("To", recipient)
	msg.SetHeader("From", m.sender)
	msg.SetHeader("Subject", subject.String())
	msg.SetBody("text/plain", plainBody.String())
	msg.AddAlternative("text/html", htmlBody.String())

	err = m.dialer.DialAndSend(msg)
	if err != nil {
		return err
	}

	return nil
}

//go:embed "templates"
var emailTemplates embed.FS
```

Create email templates in `ui/templates/email`:

1. `activation.tmpl`:
```html
{{define "subject"}}Welcome to Go WebApp!{{end}}

{{define "plainBody"}}
Hi {{.Name}},

Thanks for signing up for a Go WebApp account. We're excited to have you on board!

Please send a PUT request to the following URL to activate your account:

{{.ActivationURL}}

Thanks,
The Go WebApp Team
{{end}}

{{define "htmlBody"}}
<!doctype html>
<html>
<head>
    <meta name="viewport" content="width=device-width" />
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <title>{{template "subject" .}}</title>
</head>
<body>
    <p>Hi {{.Name}},</p>
    <p>Thanks for signing up for a Go WebApp account. We're excited to have you on board!</p>
    <p>Please click the following link to activate your account:</p>
    <p><a href="{{.ActivationURL}}">{{.ActivationURL}}</a></p>
    <p>Thanks,</p>
    <p>The Go WebApp Team</p>
</body>
</html>
{{end}}
```

2. `password-reset.tmpl`:
```html
{{define "subject"}}Password Reset Request{{end}}

{{define "plainBody"}}
Hi {{.Name}},

We received a request to reset your password. If you didn't make this request, please ignore this email.

To reset your password, please send a PUT request to the following URL:

{{.ResetURL}}

This link will expire in {{.Expiration}} hours.

Thanks,
The Go WebApp Team
{{end}}

{{define "htmlBody"}}
<!doctype html>
<html>
<head>
    <meta name="viewport" content="width=device-width" />
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <title>{{template "subject" .}}</title>
</head>
<body>
    <p>Hi {{.Name}},</p>
    <p>We received a request to reset your password. If you didn't make this request, please ignore this email.</p>
    <p>To reset your password, please click the following link:</p>
    <p><a href="{{.ResetURL}}">{{.ResetURL}}</a></p>
    <p>This link will expire in {{.Expiration}} hours.</p>
    <p>Thanks,</p>
    <p>The Go WebApp Team</p>
</body>
</html>
{{end}}
```

## Step 9: Implement User Handlers

Create `cmd/web/handlers_users.go`:

```go
package main

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/yourusername/go-webapp/internal/models"
	"github.com/go-playground/validator/v10"
)

type userSignupForm struct {
	Name                string `form:"name" validate:"required"`
	Email               string `form:"email" validate:"required,email"`
	Password            string `form:"password" validate:"required,min=8"`
	validator           *validator.Validate
}

func (app *application) userSignup(w http.ResponseWriter, r *http.Request) {
	var form userSignupForm

	err := app.decodePostForm(r, &form)
	if err != nil {
		app.clientError(w, http.StatusBadRequest)
		return
	}

	form.validator = validator.New()
	err = form.validator.Struct(form)
	if err != nil {
		app.render(w, r, "signup.page.tmpl", &templateData{
			Form: form,
		})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(form.Password), bcrypt.DefaultCost)
	if err != nil {
		app.serverError(w, r, err)
		return
	}

	user := &models.User{
		Name:         form.Name,
		Email:        form.Email,
		PasswordHash: hashedPassword,
		Activated:    false,
	}

	err = app.models.Users.Insert(user)
	if err != nil {
		if errors.Is(err, models.ErrDuplicateEmail) {
			form.AddFieldError("email", "Email address is already in use")
			app.render(w, r, "signup.page.tmpl", &templateData{
				Form: form,
			})
		} else {
			app.serverError(w, r, err)
		}
		return
	}

	token, err := app.models.Tokens.New(user.ID, 3*24*time.Hour, models.ScopeActivation)
	if err != nil {
		app.serverError(w, r, err)
		return
	}

	app.background(func() {
		data := map[string]interface{}{
			"activationToken": token.Plaintext,
			"userID":          user.ID,
		}

		err = app.mailer.Send(user.Email, "activation.tmpl", data)
		if err != nil {
			app.logger.Error().Err(err).Msg("failed to send activation email")
		}
	})

	app.sessionManager.Put(r.Context(), "flash", "Your signup was successful. Please check your email for activation instructions.")
	http.Redirect(w, r, "/user/login", http.StatusSeeOther)
}

func (app *application) activateUser(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		app.clientError(w, http.StatusBadRequest)
		return
	}

	user, err := app.models.Users.GetForToken(models.ScopeActivation, token)
	if err != nil {
		if errors.Is(err, models.ErrRecordNotFound) {
			app.clientError(w, http.StatusBadRequest)
		} else {
			app.serverError(w, r, err)
		}
		return
	}

	user.Activated = true
	err = app.models.Users.Update(user)
	if err != nil {
		app.serverError(w, r, err)
		return
	}

	err = app.models.Tokens.DeleteAllForUser(models.ScopeActivation, user.ID)
	if err != nil {
		app.serverError(w, r, err)
		return
	}

	app.sessionManager.Put(r.Context(), "flash", "Your account has been activated successfully!")
	http.Redirect(w, r, "/user/login", http.StatusSeeOther)
}

func (app *application) userLogin(w http.ResponseWriter, r *http.Request) {
	var form struct {
		Email    string `form:"email" validate:"required,email"`
		Password string `form:"password" validate:"required"`
		validator *validator.Validate
	}

	err := app.decodePostForm(r, &form)
	if err != nil {
		app.clientError(w, http.StatusBadRequest)
		return
	}

	form.validator = validator.New()
	err = form.validator.Struct(form)
	if err != nil {
		app.render(w, r, "login.page.tmpl", &templateData{
			Form: form,
		})
		return
	}

	user, err := app.models.Users.GetByEmail(form.Email)
	if err != nil {
		if errors.Is(err, models.ErrRecordNotFound) {
			form.AddFieldError("email", "Email or password is incorrect")
			app.render(w, r, "login.page.tmpl", &templateData{
				Form: form,
			})
		} else {
			app.serverError(w, r, err)
		}
		return
	}

	if !user.Activated {
		form.AddFieldError("email", "Email is not activated")
		app.render(w, r, "login.page.tmpl", &templateDataData{
			Form: form,
		})
		return
	}

	match, err := user.PasswordMatches(form.Password)
	if err != nil {
		app.serverError(w, r, err)
		return
	}

	if !match {
		form.AddFieldError("email", "Email or password is incorrect")
		app.render(w, r, "login.page.tmpl", &templateData{
			Form: form,
		})
		return
	}

	err = app.loginUser(w, r, user.ID)
	if err != nil {
		app.serverError(w, r, err)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (app *application) userLogout(w http.ResponseWriter, r *http.Request) {
	err := app.logoutUser(w, r)
	if err != nil {
		app.serverError(w, r, err)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (app *application) forgotPassword(w http.ResponseWriter, r *http.Request) {
	var form struct {
		Email string `form:"email" validate:"required,email"`
		validator *validator.Validate
	}

	err := app.decodePostForm(r, &form)
	if err != nil {
		app.clientError(w, http.StatusBadRequest)
		return
	}

	form.validator = validator.New()
	err = form.validator.Struct(form)
	if err != nil {
		app.render(w, r, "forgot-password.page.tmpl", &templateData{
			Form: form,
		})
		return
	}

	user, err := app.models.Users.GetByEmail(form.Email)
	if err != nil {
		if errors.Is(err, models.ErrRecordNotFound) {
			app.render(w, r, "forgot-password.page.tmpl", &templateData{
				Form:              form,
				EmailSent:         true,
			})
		} else {
			app.serverError(w, r, err)
		}
		return
	}

	token, err := app.models.Tokens.New(user.ID, 1*time.Hour, models.ScopePasswordReset)
	if err != nil {
		app.serverError(w, r, err)
		return
	}

	app.background(func() {
		data := map[string]interface{}{
			"passwordResetToken": token.Plaintext,
			"userID":            user.ID,
		}

		err = app.mailer.Send(user.Email, "password-reset.tmpl", data)
		if err != nil {
			app.logger.Error().Err(err).Msg("failed to send password reset email")
		}
	})

	app.render(w, r, "forgot-password.page.tmpl", &templateData{
		Form:              form,
		EmailSent:         true,
	})
}

func (app *application) resetPassword(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		app.clientError(w, http.StatusBadRequest)
		return
	}

	user, err := app.models.Users.GetForToken(models.ScopePasswordReset, token)
	if err != nil {
		if errors.Is(err, models.ErrRecordNotFound) {
			app.clientError(w, http.StatusBadRequest)
		} else {
			app.serverError(w, r, err)
		}
		return
	}

	var form struct {
		Password         string `form:"password" validate:"required,min=8"`
		ConfirmPassword  string `form:"confirmPassword" validate:"required,eqfield=Password"`
		validator        *validator.Validate
	}

	switch r.Method {
	case http.MethodGet:
		app.render(w, r, "reset-password.page.tmpl", &templateData{
			Form: form,
		})
	case http.MethodPost:
		err := app.decodePostForm(r, &form)
		if err != nil {
			app.clientError(w, http.StatusBadRequest)
			return
		}

		form.validator = validator.New()
		err = form.validator.Struct(form)
		if err != nil {
			app.render(w, r, "reset-password.page.tmpl", &templateData{
				Form: form,
			})
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(form.Password), bcrypt.DefaultCost)
		if err != nil {
			app.serverError(w, r, err)
			return
		}

		user.PasswordHash = hashedPassword
		err = app.models.Users.Update(user)
		if err != nil {
			app.serverError(w, r, err)
			return
		}

		err = app.models.Tokens.DeleteAllForUser(models.ScopePasswordReset, user.ID)
		if err != nil {
			app.serverError(w, r, err)
			return
		}

		app.sessionManager.Put(r.Context(), "flash", "Your password has been reset successfully!")
		http.Redirect(w, r, "/user/login", http.StatusSeeOther)
	}
}
```

## Step 10: Implement CRUD Handlers

Create `cmd/web/handlers_posts.go`:

```go
package main

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/yourusername/go-webapp/internal/models"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
)

type postForm struct {
	Title   string `form:"title" validate:"required,max=100"`
	Content string `form:"content" validate:"required"`
	validator *validator.Validate
}

func (app *application) createPost(w http.ResponseWriter, r *http.Request) {
	var form postForm

	err := app.decodePostForm(r, &form)
	if err != nil {
		app.clientError(w, http.StatusBadRequest)
		return
	}

	form.validator = validator.New()
	err = form.validator.Struct(form)
	if err != nil {
		app.render(w, r, "create-post.page.tmpl", &templateData{
			Form: form,
		})
		return
	}

	userID := app.sessionManager.GetInt(r.Context(), "authenticatedUserID")

	post := &models.Post{
		UserID:  userID,
		Title:   form.Title,
		Content: form.Content,
	}

	err = app.models.Posts.Insert(post)
	if err != nil {
		app.serverError(w, r, err)
		return
	}

	app.sessionManager.Put(r.Context(), "flash", "Post created successfully!")
	http.Redirect(w, r, fmt.Sprintf("/posts/%d", post.ID), http.StatusSeeOther)
}

func (app *application) showPost(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil || id < 1 {
		app.notFound(w)
		return
	}

	post, err := app.models.Posts.Get(id)
	if err != nil {
		if errors.Is(err, models.ErrRecordNotFound) {
			app.notFound(w)
		} else {
			app.serverError(w, r, err)
		}
		return
	}

	app.render(w, r, "show-post.page.tmpl", &templateData{
		Post: post,
	})
}

func (app *application) editPost(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil || id < 1 {
		app.notFound(w)
		return
	}

	post, err := app.models.Posts.Get(id)
	if err != nil {
		if errors.Is(err, models.ErrRecordNotFound) {
			app.notFound(w)
		} else {
			app.serverError(w, r, err)
		}
		return
	}

	userID := app.sessionManager.GetInt(r.Context(), "authenticatedUserID")
	if post.UserID != userID {
		app.clientError(w, http.StatusForbidden)
		return
	}

	var form postForm
	form.Title = post.Title
	form.Content = post.Content

	switch r.Method {
	case http.MethodGet:
		app.render(w, r, "edit-post.page.tmpl", &templateData{
			Form: form,
			Post: post,
		})
	case http.MethodPost:
		err := app.decodePostForm(r, &form)
		if err != nil {
			app.clientError(w, http.StatusBadRequest)
			return
		}

		form.validator = validator.New()
		err = form.validator.Struct(form)
		if err != nil {
			app.render(w, r, "edit-post.page.tmpl", &templateData{
				Form: form,
				Post: post,
			})
			return
		}

		post.Title = form.Title
		post.Content = form.Content

		err = app.models.Posts.Update(post)
		if err != nil {
			app.serverError(w, r, err)
			return
		}

		app.sessionManager.Put(r.Context(), "flash", "Post updated successfully!")
		http.Redirect(w, r, fmt.Sprintf("/posts/%d", post.ID), http.StatusSeeOther)
	}
}

func (app *application) deletePost(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil || id < 1 {
		app.notFound(w)
		return
	}

	post, err := app.models.Posts.Get(id)
	if err != nil {
		if errors.Is(err, models.ErrRecordNotFound) {
			app.notFound(w)
		} else {
			app.serverError(w, r, err)
		}
		return
	}

	userID := app.sessionManager.GetInt(r.Context(), "authenticatedUserID")
	if post.UserID != userID {
		app.clientError(w, http.StatusForbidden)
		return
	}

	err = app.models.Posts.Delete(id)
	if err != nil {
		app.serverError(w, r, err)
		return
	}

	app.sessionManager.Put(r.Context(), "flash", "Post deleted successfully!")
	http.Redirect(w, r, "/posts", http.StatusSeeOther)
}

func (app *application) listPosts(w http.ResponseWriter, r *http.Request) {
	posts, err := app.models.Posts.Latest()
	if err != nil {
		app.serverError(w, r, err)
		return
	}

	app.render(w, r, "posts.page.tmpl", &templateData{
		Posts: posts,
	})
}
```

## Step 11: Implement Middleware

Create `cmd/web/middleware.go`:

```go
package main

import (
	"net/http"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/justinas/nosurf"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
)

func (app *application) routes() http.Handler {
	router := chi.NewRouter()

	// Middleware
	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(middleware.Recoverer)
	router.Use(middleware.Timeout(60 * time.Second))
	router.Use(app.sessionManager.LoadAndSave)
	router.Use(nosurf.New)
	router.Use(app.authenticate)
	router.Use(hlog.NewHandler(app.logger))
	router.Use(hlog.AccessHandler(func(r *http.Request, status, size int, duration time.Duration) {
		hlog.FromRequest(r).Info().
			Str("method", r.Method).
			Str("url", r.URL.String()).
			Int("status", status).
			Int("size", size).
			Dur("duration", duration).
			Msg("")
	}))
	router.Use(hlog.RemoteAddrHandler("ip"))
	router.Use(hlog.UserAgentHandler("user_agent"))
	router.Use(hlog.RefererHandler("referer"))
	router.Use(hlog.RequestIDHandler("request_id", "Request-Id"))

	// Rate limiting
	if app.config.limiter.enabled {
		router.Use(app.rateLimit)
	}

	// Static files
	fileServer := http.FileServer(http.Dir("./ui/static"))
	router.Handle("/static/*", http.StripPrefix("/static", fileServer))

	// Home
	router.Get("/", app.home)

	// User routes
	router.Route("/user", func(r chi.Router) {
		r.Get("/signup", app.userSignupForm)
		r.Post("/signup", app.userSignup)
		r.Get("/login", app.userLoginForm)
		r.Post("/login", app.userLogin)
		r.Post("/logout", app.userLogout)
		r.Get("/forgot-password", app.forgotPasswordForm)
		r.Post("/forgot-password", app.forgotPassword)
		r.Get("/reset-password", app.resetPasswordForm)
		r.Post("/reset-password", app.resetPassword)
	})

	// Post routes
	router.Route("/posts", func(r chi.Router) {
		r.Get("/", app.listPosts)
		r.Get("/{id}", app.showPost)

		// Authenticated routes
		r.Group(func(r chi.Router) {
			r.Use(app.requireAuthentication)
			r.Get("/create", app.createPostForm)
			r.Post("/create", app.createPost)
			r.Get("/{id}/edit", app.editPost)
			r.Post("/{id}/edit", app.editPost)
			r.Post("/{id}/delete", app.deletePost)
		})
	})

	// Admin routes
	router.Route("/admin", func(r chi.Router) {
		r.Use(app.requireRole("admin"))
		r.Get("/", app.adminDashboard)
	})

	return router
}

func (app *application) rateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if app.config.limiter.enabled {
			ip := r.RemoteAddr
			limiter := app.getLimiter(ip)

			if !limiter.Allow() {
				app.rateLimitExceededResponse(w, r)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("X-Frame-Options", "deny")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' fonts.googleapis.com; font-src fonts.gstatic.com")

		next.ServeHTTP(w, r)
	})
}
```

## Step 12: Implement Templates

Create base template `ui/html/base.layout.tmpl`:

```html
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{template "title" .}} - Go WebApp</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="/static/css/main.css" rel="stylesheet" type="text/css">
</head>
<body>
    {{template "navbar" .}}

    <main class="container mt-4">
        {{with .Flash}}
        <div class="alert alert-success">{{.}}</div>
        {{end}}
        {{template "main" .}}
    </main>

    {{template "footer" .}}
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="/static/js/main.js" type="text/javascript"></script>
</body>
</html>
```

Create navbar partial `ui/html/partials/navbar.tmpl`:

```html
{{define "navbar"}}
<nav class="navbar navbar-expand-lg navbar-dark bg-dark">
    <div class="container">
        <a class="navbar-brand" href="/">Go WebApp</a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav me-auto">
                <li class="nav-item">
                    <a class="nav-link" href="/">Home</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="/posts">Posts</a>
                </li>
            </ul>
            <ul class="navbar-nav">
                {{if .IsAuthenticated}}
                <li class="nav-item">
                    <a class="nav-link" href="/posts/create">Create Post</a>
                </li>
                <li class="nav-item">
                    <form action="/user/logout" method="POST">
                        <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
                        <button type="submit" class="btn btn-link nav-link">Logout</button>
                    </form>
                </li>
                {{else}}
                <li class="nav-item">
                    <a class="nav-link" href="/user/signup">Signup</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="/user/login">Login</a>
                </li>
                {{end}}
            </ul>
        </div>
    </div>
</nav>
{{end}}
```

Create home page template `ui/html/home.page.tmpl`:

```html
{{template "base" .}}

{{define "title"}}Home{{end}}

{{define "main"}}
<div class="jumbotron">
    <h1 class="display-4">Welcome to Go WebApp!</h1>
    <p class="lead">This is a simple web application built with Go and SQLite.</p>
    <hr class="my-4">
    <p>It includes user authentication, CRUD operations, and more.</p>
    {{if not .IsAuthenticated}}
    <a class="btn btn-primary btn-lg" href="/user/signup" role="button">Sign up</a>
    {{end}}
</div>
{{end}}
```

## Step 13: Implement HTTPS Support

Create `cmd/web/tls.go`:

```go
package main

import (
	"crypto/tls"
	"log"
	"os"
)

func (app *application) loadTLSCertificates() (*tls.Config, error) {
	// In production, you should get these from a secure location
	// For development, you can generate self-signed certificates:
	// $ openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout key.pem -out cert.pem

	cert, err := tls.LoadX509KeyPair("tls/cert.pem", "tls/key.pem")
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
	}, nil
}

func generateSelfSignedCert() {
	// This would be a function to generate self-signed certs for development
	// In production, you should use certificates from a proper CA
}
```

## Step 14: Create Dockerfile

Create `Dockerfile`:

```dockerfile
# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -o webapp ./cmd/web

# Runtime stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /app

COPY --from=builder /app/webapp .
COPY --from=builder /app/migrations ./migrations
COPY --from=builder /app/ui ./ui

# Generate self-signed cert for development (remove in production)
RUN apk --no-cache add openssl && \
    mkdir tls && \
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout tls/key.pem -out tls/cert.pem \
    -subj "/C=US/ST=California/L=San Francisco/O=Go WebApp/CN=localhost"

ENV PORT=4000
ENV ENV=production
ENV DB_DSN=/data/webapp.db

VOLUME /data

EXPOSE 4000

CMD ["./webapp"]
```

## Step 15: Create docker-compose.yml

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  web:
    build: .
    ports:
      - "4000:4000"
    volumes:
      - ./data:/data
    environment:
      - PORT=4000
      - ENV=development
      - DB_DSN=/data/webapp.db
      - SMTP_HOST=smtp.mailtrap.io
      - SMTP_PORT=2525
      - SMTP_USERNAME=your-mailtrap-username
      - SMTP_PASSWORD=your-mailtrap-password
      - SMTP_SENDER="Go WebApp <no-reply@example.com>"
      - SECRET_KEY=your-secret-key
    restart: unless-stopped
```

## Step 16: Create Makefile

Create `Makefile`:

```makefile
.PHONY: build run test migrate-up migrate-down docker-build docker-run

build:
	go build -o bin/webapp ./cmd/web

run: build
	./bin/webapp

test:
	go test -v ./...

migrate-up:
	goose -dir migrations sqlite3 webapp.db up

migrate-down:
	goose -dir migrations sqlite3 webapp.db down

docker-build:
	docker-compose build

docker-run:
	docker-compose up -d
```

## Step 17: Testing

Create `internal/models/users_test.go`:

```go
package models

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestUserModel(t *testing.T) {
	if testing.Short() {
		t.Skip("models: skipping integration test")
	}

	tests := []struct {
		name string
		test func(*testing.T, *sqlx.DB)
	}{
		{
			name: "Insert and GetByEmail",
			test: testUserInsertAndGetByEmail,
		},
		{
			name: "PasswordMatches",
			test: testPasswordMatches,
		},
	}

	db, err := InitDB("file:test.db?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	models := NewModels(db)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Start with a clean database for each test
			_, err := db.Exec("DROP TABLE IF EXISTS users")
			if err != nil {
				t.Fatal(err)
			}

			_, err = db.Exec(`CREATE TABLE users (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				name TEXT NOT NULL,
				email TEXT NOT NULL UNIQUE,
				password_hash TEXT NOT NULL,
				role TEXT NOT NULL DEFAULT 'user',
				activated BOOLEAN NOT NULL DEFAULT FALSE,
				created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
				updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
			)`)
			if err != nil {
				t.Fatal(err)
			}

			tt.test(t, db)
		})
	}
}

func testUserInsertAndGetByEmail(t *testing.T, db *sqlx.DB) {
	models := NewModels(db)

	user := &User{
		Name:      "Test User",
		Email:     "test@example.com",
		PasswordHash: []byte("password"),
		Activated: true,
	}

	err := models.Users.Insert(user)
	assert.NoError(t, err)
	assert.NotZero(t, user.ID)
	assert.WithinDuration(t, time.Now(), user.CreatedAt, time.Second)
	assert.WithinDuration(t, time.Now(), user.UpdatedAt, time.Second)

	fetchedUser, err := models.Users.GetByEmail("test@example.com")
	assert.NoError(t, err)
	assert.Equal(t, user.ID, fetchedUser.ID)
	assert.Equal(t, user.Name, fetchedUser.Name)
	assert.Equal(t, user.Email, fetchedUser.Email)
	assert.Equal(t, user.PasswordHash, fetchedUser.PasswordHash)
	assert.Equal(t, user.Activated, fetchedUser.Activated)
}

func testPasswordMatches(t *testing.T, db *sqlx.DB) {
	models := NewModels(db)

	password := "password123"
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	assert.NoError(t, err)

	user := &User{
		Name:      "Test User",
		Email:     "test@example.com",
		PasswordHash: hashedPassword,
		Activated: true,
	}

	err = models.Users.Insert(user)
	assert.NoError(t, err)

	match, err := models.Users.PasswordMatches(user, password)
	assert.NoError(t, err)
	assert.True(t, match)

	match, err = models.Users.PasswordMatches(user, "wrongpassword")
	assert.NoError(t, err)
	assert.False(t, match)
}
```

## Step 18: Run the Application

```bash
# Build and run with Docker
make docker-build
make docker-run

# Or run locally
make migrate-up
make build
make run
```

The application will be available at `https://localhost:4000` (with self-signed certificate) or `http://localhost:4000` if you disable HTTPS in development.

## Summary

This comprehensive guide covers:
1. Project setup with Go modules
2. SQLite database integration
3. User authentication (signup, login, logout)
4. Role-based access control
5. Email verification and password reset
6. CRUD operations for posts
7. Rate limiting
8. Input validation
9. Logging with zerolog
10. Testing
11. HTTPS support
12. Docker containerization
13. Bootstrap for styling

The application follows best practices for security, performance, and maintainability. You can extend it further by adding more features like API endpoints, additional resources, or more complex role hierarchies.