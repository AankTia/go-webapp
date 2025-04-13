package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/AankTia/go-webapp/internal/models"
	"github.com/rs/zerolog"
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

	flag.IntVar(&cfg.port, "port", 4000, "API Server port")
	flag.StringVar(&cfg.env, "env", "development", "Environemnt (development|staging|production)")
	flag.StringVar(&cfg.db.dsn, "db-dsn", "webapp.db", "SQLite DSN")
	flag.StringVar(&cfg.smtp.host, "smtp-host", "smtp.mailtrap.io", "SMTP host")
	flag.IntVar(&cfg.smtp.port, "smtp-port", 587, "SMTP port")
	flag.StringVar(&cfg.smtp.username, "smtp-username", "", "SMTP username")
	flag.StringVar(&cfg.smtp.password, "smtp-password", "", "SMTP password")
	flag.StringVar(&cfg.smtp.sender, "smtp-sender", "Go Webapp <no-reply@example.com>", "SMTP sender")
	flag.StringVar(&cfg.secretKey, "secret-key", "secret-key", "Secret key")
	flag.Parse()

	// Initial logger
	logger := zerolog.New(os.Stdout).With().Timestamp().Logger()

	// Connect to database
	db, err := models.InitDB(cfg.db.dsn)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to connect to database")
	}
	defer db.Close()

	// Run migration
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
		Addr: fmt.Sprint(":%d", cfg.port),
		Handler: app.routes(),
		IdleTimeout: time.Minute,
		ReadTimeout: 10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	// Graceful shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal().Err(err).Msg("faild to start server")
		}
	}()

	logger.Info().Msgf("starting %s server on %s", cfg.env, srv.Addr)

	<-done
	logger.Info().Msg("server stoped")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Fatal().Err(err).Msg("server shotwon failed")
	}

	logger.Info().Msg("Server exites properly")
}

func runMigrations(dsn string) error {
	// Implementation for running migrations using goose
	return nil
}
