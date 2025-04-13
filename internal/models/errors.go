package models

import "errors"

var (
	// ErrRecordNotFound is returned when a record doesn't exist in database
	ErrRecordNotFound = errors.New("record not found")

	// ErrDuplicateEmail is returned when a user tries to register with an email that's already in use
	ErrDuplicateEmail = errors.New("duplicate email")

	// ErrInvalidCredentials is returned when a user provides invalid credentials
	ErrInvalidCredentials = errors.New("invalid credentials")

	// ErrInvalidToken is returned when a token is invalid or expired
	ErrInvalidToken = errors.New("invalid token")
)