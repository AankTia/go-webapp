package main

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/AankTia/go-webapp/internal/models"
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