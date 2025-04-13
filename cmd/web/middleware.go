package main

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/justinas/nosurf"
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