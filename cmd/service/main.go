package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/basedalex/avito-backend-2025-spring/internal/config"
	"github.com/basedalex/avito-backend-2025-spring/internal/db"
	dto "github.com/basedalex/avito-backend-2025-spring/internal/generated"
	"github.com/basedalex/avito-backend-2025-spring/internal/middleware"
	"github.com/basedalex/avito-backend-2025-spring/internal/service"
	"github.com/go-chi/chi/v5"
	"github.com/sirupsen/logrus"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cfg, err := config.Init("./config.dev.yaml")
	if err != nil {
		log.Fatal("Error loading config: ", err)
		return
	}

	log.Println("new build")

	database, err := db.NewPostgres(ctx, cfg)
	if err != nil {
		log.Fatal("Error connecting to database: ", err)
		return
	}
	log.Println("connected to database")

	
	server := service.NewService(database, logrus.New())
	r := chi.NewRouter()
	r.Use(middleware.Authentication)

	dto.HandlerFromMux(server, r)

	srv := &http.Server{
		Addr:    ":8080",
		Handler: r,
	}

	go func() {
		log.Println("Server listening on port 8080")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("ListenAndServe Error: ", err)
		}
	}()

	<-ctx.Done()

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()

	log.Println("Shutting down server...")
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatal("Server Shutdown Error: ", err)
	}
	log.Println("Server gracefully stopped")
}