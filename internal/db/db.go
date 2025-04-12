package db

import (
	"context"
	"fmt"
	"time"

	"github.com/basedalex/avito-backend-2025-spring/internal/config"
	"github.com/basedalex/avito-backend-2025-spring/internal/db/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:generate mockgen -source=db.go -destination=../mocks/mock_db.go -package=mocks
type Repository interface {
	RegisterUser(ctx context.Context, user models.User) error
	GetUserByEmail(email string) (models.User, error)
	CreatePVZ(ctx context.Context, pvz models.PVZ) error 
	CreateReception(ctx context.Context, reception *models.Reception) error
	AddProducts(ctx context.Context, reception *models.Product) error
	DeleteLastProduct(pvz_id string) error
	CloseLastReception(pvz_id string) error
	GetPVZInfo(startDate, endDate time.Time, page, limit int) (PVZWithReceptions, error)
	CheckReceptionStatus(ctx context.Context, pvz_id uuid.UUID) (string,error)
}

type PVZWithReceptions struct {
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
func (p *Postgres) RegisterUser(ctx context.Context, user models.User) error {
	tx, err := p.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("error starting transaction: %w", err)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	_, err = p.db.Exec(ctx, "INSERT INTO users (id, email, password, role) VALUES ($1, $2, $3, $4)", user.ID, user.Email, user.Password, user.Role)
	if err != nil {
		return fmt.Errorf("could not create new user: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("error committing transaction: %w", err)
	}

	return nil
}
// GetUserByEmail well... gets user by email
func (p *Postgres) GetUserByEmail(email string) (models.User, error) {
	var user models.User

	query := `SELECT id, email, password, role FROM users WHERE email = $1`
	err := p.db.QueryRow(context.Background(), query, email).Scan(&user.ID, &user.Email, &user.Password, &user.Role)
	if err != nil {
		return models.User{}, fmt.Errorf("error getting user by email: %w", err)
	}

	return user, nil
}

// CreatePVZ creates a new PVZ 
func (p *Postgres) CreatePVZ(ctx context.Context, pvz models.PVZ) error {
	tx, err := p.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("error starting transaction: %w", err)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	_, err = p.db.Exec(ctx, "INSERT INTO pvz (id, registration_date, city) VALUES ($1, $2, $3)", pvz.ID, pvz.RegistrationDate, pvz.City)
	if err != nil {
		return fmt.Errorf("could not create new pvz: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("error committing transaction: %w", err)
	}

	return nil
}

func (p *Postgres) CheckReceptionStatus(ctx context.Context, pvz_id uuid.UUID) (string, error)  {
	var status string

	query := `SELECT status FROM receptions WHERE pvz_id = $1`
	err := p.db.QueryRow(context.Background(), query, pvz_id).Scan(&status)
	if err != nil {
		return "", fmt.Errorf("error getting reception by email: %w", err)
	}

	if status == "" {
		return "close", nil
	}

	return status, nil
}

func (p *Postgres) CreateReception(ctx context.Context, reception *models.Reception) error {
	query := `INSERT INTO receptions (id, recieved_at, pvz_id, status) VALUES ($1, $2, $3, $4)`
	_, err := p.db.Exec(ctx, query, reception.ID, reception.ReceivedAt, reception.PVZID, reception.Status)
	if err != nil {
		return fmt.Errorf("could not create new reception: %w", err)
	}

	return nil
}

func (p *Postgres) AddProducts(ctx context.Context, reception *models.Product) error {
	query := `INSERT INTO products (id, received_at, product_type, reception_id) VALUES ($1, $2)`
	_, err := p.db.Exec(ctx, query, reception.ID, reception.ReceivedAt, reception.Type, reception.ReceptionID)
	if err != nil {
		return fmt.Errorf("could not create new product: %w", err)
	}
	return nil
}

func (p *Postgres) DeleteLastProduct(pvz_id string) error {
	return nil
}

func (p *Postgres) CloseLastReception(pvz_id string) error {
	return nil
}

func (p *Postgres) GetPVZInfo(startDate, endDate time.Time, page, limit int) (PVZWithReceptions, error) {
	return PVZWithReceptions{}, nil
}