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
	"github.com/basedalex/avito-backend-2025-spring/internal/router"
	"github.com/basedalex/avito-backend-2025-spring/internal/service"
)

// DTO GEN command with oapi-codegen
// oapi-codegen --package=dto --generate=models swagger.yaml > dto/dto.gen.go

// DTO without oapi-codegen install go run github.com/deepmap/oapi-codegen/cmd/oapi-codegen@latest \
//   --package=dto \
//   --generate=models \
//    swagger.yaml > dto/dto.gen.go

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cfg, err := config.Init("./config.dev.yaml")
	if err != nil {
		log.Fatal("Error loading config: ", err)
		return
	}

	database, err := db.NewPostgres(ctx, cfg)
	if err != nil {
		log.Fatal("Error connecting to database: ", err)
		return
	}
	log.Println("connected to database")

	server := service.NewService(database)
	r := router.NewRouter(server)

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