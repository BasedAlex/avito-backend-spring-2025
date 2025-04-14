package tests

import (
	"context"
	"testing"
	"time"

	"github.com/basedalex/avito-backend-2025-spring/internal/config"
	"github.com/basedalex/avito-backend-2025-spring/internal/db"
	"github.com/basedalex/avito-backend-2025-spring/internal/db/models"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestFullReceptionFlow(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	cfg := &config.Config{
		Database: struct {
			DSN        string `yaml:"dsn"`
			Migrations string `yaml:"migrations"`
		}{
			DSN:        "postgres://postgres:password@localhost:5433/avito-shop?sslmode=disable",
			Migrations: "../migrations",
		},
	}

	db, err := db.NewPostgres(ctx, cfg)
	require.NoError(t, err)

	pvzID := uuid.New()
	newPVZ := models.PVZ{
		ID:      pvzID,
		RegistrationDate: time.Now().UTC(),
		City: "Moscow",
	}
	createdPVZ, err := db.CreatePVZ(ctx, newPVZ)
	require.NoError(t, err)
	require.Equal(t, newPVZ.ID, createdPVZ.ID)

	reception := &models.Reception{
		ID: uuid.New(),
		PVZID: createdPVZ.ID,
	}
	createdReception, err := db.CreateReception(ctx, reception)
	require.NoError(t, err)
	require.Equal(t, createdReception.PVZID, createdPVZ.ID)

	for i := 1; i <= 50; i++ {
		product := &models.Product{
			ID: uuid.New(),
			ReceivedAt: time.Now().UTC(),
			Type: "shoes",
			ReceptionID: createdReception.ID,
		}
		addedProduct, err := db.AddProducts(ctx, product, createdPVZ.ID)
		require.NoError(t, err)
		require.Equal(t, product.Type, addedProduct.Type)
	}

	closedReception, err := db.CloseLastReception(ctx, createdPVZ)
	require.NoError(t, err)
	require.Equal(t, createdPVZ.ID, closedReception.PVZID)
}