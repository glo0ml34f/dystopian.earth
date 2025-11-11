package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"dystopian.earth/internal/config"
	"dystopian.earth/internal/server"
	"dystopian.earth/internal/storage"
)

func main() {
	cfg := config.FromEnv()

	db, err := storage.Open(cfg.DSN)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := storage.Migrate(ctx, db); err != nil {
		log.Fatalf("apply migrations: %v", err)
	}

	templates, err := server.NewTemplates(cfg.TemplatesDir)
	if err != nil {
		log.Fatalf("load templates: %v", err)
	}

	srv, err := server.New(cfg, db, templates)
	if err != nil {
		log.Fatalf("init server: %v", err)
	}

	httpServer := &http.Server{
		Addr:    cfg.Addr,
		Handler: srv.Routes(),
	}

	go func() {
		log.Printf("portal listening on %s", cfg.Addr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
	}
	log.Println("portal stopped")
}
