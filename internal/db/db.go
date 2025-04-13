package db

import (
	"context"
	"fmt"
	"time"

	"github.com/basedalex/avito-backend-2025-spring/internal/config"
	"github.com/basedalex/avito-backend-2025-spring/internal/db/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose"
)

//go:generate mockgen -source=db.go -destination=../mocks/mock_db.go -package=mocks
type Repository interface {
	RegisterUser(ctx context.Context, user models.User) error
	GetUserByEmail(email string) (models.User, error)
	CreatePVZ(ctx context.Context, pvz models.PVZ) error 
	CreateReception(ctx context.Context, reception *models.Reception) error
	AddProducts(ctx context.Context, reception *models.Product, PVZID uuid.UUID) error
	DeleteLastProduct(ctx context.Context, pvz models.PVZ) error 
	CloseLastReception(ctx context.Context, pvz models.PVZ) error
	GetPVZInfo(ctx context.Context, startDate, endDate time.Time, page, limit int) (models.PVZWithReceptions, error) 
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

	if err := runMigrations(db, cfg.Database.Migrations); err != nil {
		return nil, fmt.Errorf("error running migrations: %w", err)
	}

	return &Postgres{db: db}, nil
}

func runMigrations(db *pgxpool.Pool, path string) error {
	sqlDB := stdlib.OpenDBFromPool(db)

	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("failed to set dialect: %w", err)
	}

	if err := goose.Up(sqlDB, path); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	if err := sqlDB.Close(); err != nil {
		return fmt.Errorf("failed to close SQL DB: %w", err)
	}

	return nil
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
	if err != nil && err != pgx.ErrNoRows {
		return "", fmt.Errorf("error getting reception by pvz_id: %w", err)
	}

	if status == "" || err == pgx.ErrNoRows {
		return "close", nil
	}

	return status, nil
}

func (p *Postgres) CreateReception(ctx context.Context, reception *models.Reception) error {
	// TODO tx
	query := `INSERT INTO receptions (id, received_at, pvz_id, status) VALUES ($1, $2, $3, $4)`
	_, err := p.db.Exec(ctx, query, reception.ID, reception.ReceivedAt, reception.PVZID, "in_progress")
	if err != nil {
		return fmt.Errorf("could not create new reception: %w", err)
	}

	query = `UPDATE pvz SET last_reception_id = $1 WHERE id = $2`
	_, err = p.db.Exec(ctx, query, reception.ID, reception.PVZID)
	if err != nil {
		return fmt.Errorf("could not create new reception: %w", err)
	}

	return nil
}

func (p *Postgres) AddProducts(ctx context.Context, reception *models.Product, PVZID uuid.UUID) error {
	fmt.Println("PVZID", PVZID)
	receptionID, err := p.GetLastReceptionID(ctx, PVZID)
	if err != nil {
		return err
	}

	fmt.Println("receptionID", receptionID)
	
	reception.ReceptionID = receptionID

	fmt.Println("RECEPTION", reception)

	query := `INSERT INTO products (id, received_at, type, reception_id) VALUES ($1, $2, $3, $4)`
	_, err = p.db.Exec(ctx, query, reception.ID, reception.ReceivedAt, reception.Type, reception.ReceptionID)
	if err != nil {
		return fmt.Errorf("could not create new product: %w", err)
	}
	return nil
}

func (p *Postgres) DeleteLastProduct(ctx context.Context, pvz models.PVZ) error {
	status, err := p.CheckReceptionStatus(ctx, pvz.ID)
	if err != nil {
		return fmt.Errorf("error getting reception status: %w", err)
	}

	if status != "in_progress" {
		return fmt.Errorf("reception is not in progress")
	}

	receptionID, err := p.GetLastReceptionID(ctx, pvz.ID)
	if err != nil {
		return err
	}
	var productID uuid.UUID
	query := `SELECT id from products WHERE reception_id = $1 ORDER BY id DESC LIMIT 1`
	err = p.db.QueryRow(ctx, query, receptionID).Scan(&productID)
	if err != nil {
		return fmt.Errorf("error getting product_id: %w", err)
	}

	query = `DELETE FROM products WHERE id = $1`
	_, err = p.db.Exec(ctx, query, productID)
	if err != nil {
		return fmt.Errorf("error deleting product: %w", err)
	}

	return nil
}

func (p *Postgres) GetLastReceptionID(ctx context.Context, pvz_id uuid.UUID) (uuid.UUID, error) {
	var receptionID uuid.UUID
	query := `SELECT last_reception_id from pvz WHERE id = $1` 
	err := p.db.QueryRow(ctx, query, pvz_id).Scan(&receptionID)
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("error getting reception_id: %w", err)
	}
	return receptionID, nil
}

func (p *Postgres) CloseLastReception(ctx context.Context, pvz models.PVZ) error {

	tx, err := p.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("error starting transaction: %w", err)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	status, err := p.CheckReceptionStatus(ctx, pvz.ID)
	if err != nil {
		return fmt.Errorf("error getting reception status: %w", err)
	}

	if status != "in_progress" {
		return fmt.Errorf("reception is not in progress")
	}

	query := `UPDATE receptions SET status = 'close' WHERE pvz_id = $1`
	_, err = p.db.Exec(ctx, query, pvz.ID)
	if err != nil {
		return fmt.Errorf("error closing reception: %w", err)
	}
	receptionID, err := p.GetLastReceptionID(ctx, pvz.ID)
	if err != nil {
		return err
	}
	query = `update pvz set last_reception_id = $2 WHERE id = $1`
	_, err = p.db.Exec(ctx, query, pvz.ID, receptionID)
	if err != nil {
		return fmt.Errorf("error updating pvz: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("error committing transaction: %w", err)
	}

	return nil
}

func (p *Postgres) GetPVZInfo(ctx context.Context, startDate, endDate time.Time, page, limit int) (models.PVZWithReceptions, error) {
    offset := (page - 1) * limit
    
    query := `
        WITH filtered_receptions AS (
            SELECT r.id as reception_id, r.received_at, r.pvz_id, r.status
            FROM receptions r
            WHERE ($1::timestamp IS NULL OR r.received_at >= $1)
            AND ($2::timestamp IS NULL OR r.received_at <= $2)
        ),
        pvz_with_receptions AS (
            SELECT 
                p.id as pvz_id, 
                p.registration_date, 
                p.city,
                p.last_reception_id,
                fr.reception_id,
                fr.received_at,
                fr.status
            FROM pvz p
            LEFT JOIN filtered_receptions fr ON p.id = fr.pvz_id
            ORDER BY p.registration_date DESC
            LIMIT $3 OFFSET $4
        )
        SELECT 
            pwr.pvz_id, 
            pwr.registration_date, 
            pwr.city,
            pwr.last_reception_id,
            pwr.reception_id,
            pwr.received_at,
            pwr.status,
            pr.id as product_id,
            pr.received_at as product_received_at,
            pr.type as product_type
        FROM pvz_with_receptions pwr
        LEFT JOIN products pr ON pwr.reception_id = pr.reception_id
        ORDER BY pwr.registration_date DESC, pwr.received_at DESC, pr.received_at DESC
    `
    
    rows, err := p.db.Query(ctx, query, startDate, endDate, limit, offset)
    if err != nil {
        return models.PVZWithReceptions{}, fmt.Errorf("failed to query PVZ info: %w", err)
    }
    defer rows.Close()
    
    result := models.PVZWithReceptions{
        PVZs: make([]models.PVZReceptions, 0),
        Page: page,
        Limit: limit,
    }
    
    pvzMap := make(map[uuid.UUID]*models.PVZReceptions)
    receptionMap := make(map[uuid.UUID]*models.ReceptionProducts)
    
    for rows.Next() {
        var (
            pvzID, lastReceptionID uuid.UUID
            city string
            registrationDate time.Time
            receptionID *uuid.UUID
            receivedAt *time.Time
            status *string
            productID *uuid.UUID
            productReceivedAt *time.Time
            productType *string
        )
        
        err := rows.Scan(
            &pvzID, 
            &registrationDate, 
            &city, 
            &lastReceptionID,
            &receptionID, 
            &receivedAt, 
            &status,
            &productID,
            &productReceivedAt,
            &productType,
        )
        if err != nil {
            return models.PVZWithReceptions{}, fmt.Errorf("failed to scan PVZ row: %w", err)
        }
        
        pvzItem, exists := pvzMap[pvzID]
        if !exists {
            newPVZ := models.PVZ{
                ID:               pvzID,
                RegistrationDate: registrationDate,
                City:             city,
                LastReceptionID:  lastReceptionID,
            }
            
            newPVZReceptions := models.PVZReceptions{
                PVZ:        newPVZ,
                Receptions: make([]models.ReceptionProducts, 0),
            }
            
            pvzMap[pvzID] = &newPVZReceptions
            result.PVZs = append(result.PVZs, newPVZReceptions)
            pvzItem = &result.PVZs[len(result.PVZs)-1]
        }
        
        if receptionID != nil {
            receptionItem, receptionExists := receptionMap[*receptionID]
            if !receptionExists {
                newReception := models.Reception{
                    ID:        *receptionID,
                    ReceivedAt: *receivedAt,
                    PVZID:     pvzID,
                    Status:    *status,
                }
                
                newReceptionProducts := models.ReceptionProducts{
                    Reception: newReception,
                    Products:  make([]models.Product, 0),
                }
                
                receptionMap[*receptionID] = &newReceptionProducts
                pvzItem.Receptions = append(pvzItem.Receptions, newReceptionProducts)
                receptionItem = &pvzItem.Receptions[len(pvzItem.Receptions)-1]
            }
            
            if productID != nil {
                product := models.Product{
                    ID:          *productID,
                    ReceivedAt:  *productReceivedAt,
                    Type:        *productType,
                    ReceptionID: *receptionID,
                }
                receptionItem.Products = append(receptionItem.Products, product)
            }
        }
    }
    
    if err = rows.Err(); err != nil {
        return models.PVZWithReceptions{}, fmt.Errorf("error iterating PVZ rows: %w", err)
    }
    
    countQuery := `
        SELECT COUNT(DISTINCT p.id) 
        FROM pvz p
        LEFT JOIN receptions r ON p.id = r.pvz_id
        WHERE ($1::timestamp IS NULL OR r.received_at >= $1)
        AND ($2::timestamp IS NULL OR r.received_at <= $2)
    `
    
    var totalCount int
    err = p.db.QueryRow(ctx, countQuery, startDate, endDate).Scan(&totalCount)
    if err != nil {
        return models.PVZWithReceptions{}, fmt.Errorf("failed to count total PVZ: %w", err)
    }
    
    result.Total = totalCount
    
    return result, nil
}