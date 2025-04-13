package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strconv"
	"time"
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