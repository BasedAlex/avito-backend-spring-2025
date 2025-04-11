package db

import (
	"context"
	"fmt"

	"github.com/basedalex/avito-backend-2025-spring/internal/config"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:generate mockgen -source=db.go -destination=../mocks/mock_db.go -package=mocks
type Repository interface {
	RegisterUser() error
	LoginUser() (string, error)
	CreatePVZ(city string) error 
}

type Postgres struct {
	db *pgxpool.Pool
}

func NewPostgres(ctx context.Context, cfg *config.Config) (*Postgres, error) {
	config, err := pgxpool.ParseConfig(cfg.Database.DSN)
	if err != nil {
		return nil, fmt.Errorf("error parsing connection string: %w", err)
	}

	db, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("error connecting to database: %w", err)
	}

	err = db.Ping(ctx)
	if err != nil {
		return nil, fmt.Errorf("error pinging the database: %w", err)
	}

	return &Postgres{db: db}, nil
}

// RegisterUser registers a new user in the database.
func (p *Postgres) RegisterUser() error {
	return nil
}
// LoginUser logs in a user and returns their role.
func (p *Postgres) LoginUser() (string, error) {
	return "client", nil
}

func (p *Postgres) CreatePVZ(city string) error {
	return nil
}