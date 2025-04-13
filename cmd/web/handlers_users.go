package main

import (
	"errors"
	"net/http"

	"github.com/AankTia/go-webapp/internal/models"
	"github.com/go-playground/validator/v10"
	"golang.org/x/crypto/bcrypt"
)

type userSignupForm struct {
	Name      string `form:"name" validate:"required"`
	Email     string `form:"email" validate:"required,email"`
	Password  string `form:"password" validate:"required,min=8"`
	validator *validator.Validate
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
		Email     string `form:"email" validate:"required,email"`
		Password  string `form:"password" validate:"required"`
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
		Email     string `form:"email" validate:"required,email"`
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
				Form:      form,
				EmailSent: true,
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
			"userID":             user.ID,
		}

		err = app.mailer.Send(user.Email, "password-reset.tmpl", data)
		if err != nil {
			app.logger.Error().Err(err).Msg("failed to send password reset email")
		}
	})

	app.render(w, r, "forgot-password.page.tmpl", &templateData{
		Form:      form,
		EmailSent: true,
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
		Password        string `form:"password" validate:"required,min=8"`
		ConfirmPassword string `form:"confirmPassword" validate:"required,eqfield=Password"`
		validator       *validator.Validate
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
