package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/basedalex/avito-backend-2025-spring/internal/auth"
	"github.com/basedalex/avito-backend-2025-spring/internal/db/models"
	dto "github.com/basedalex/avito-backend-2025-spring/internal/generated"
	"github.com/basedalex/avito-backend-2025-spring/internal/mocks"
	"github.com/go-chi/chi/v5"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

func TestNewService(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockDB := mocks.NewMockRepository(ctrl)

	service := NewService(mockDB, logrus.New())

	assert.NotNil(t, service)
	assert.Equal(t, mockDB, service.db)

	_, ok := service.tokens.(JWTTokenManager)
	assert.True(t, ok, "tokens must be JWTTokenManager")
}

func TestPostDummyLogin(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockTokens := mocks.NewMockTokenManager(ctrl)

	s := &MyService{
		tokens: mockTokens,
		logger: logrus.New(),
	}

	t.Run("dummy login success - employee", func(t *testing.T) {
		loginReq := struct {
			Role string `json:"role"`
		}{
			Role: "employee",
		}

		expectedToken := "dummy-token"

		mockTokens.EXPECT().
			CreateToken("employee", "employee@mail.ru").
			Return(expectedToken, nil)

		requestBody, _ := json.Marshal(loginReq)
		req := httptest.NewRequest(http.MethodPost, "/dummyLogin", bytes.NewBuffer(requestBody))
		w := httptest.NewRecorder()

		s.PostDummyLogin(w, req)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)

		var response map[string]string
		err := json.NewDecoder(w.Body).Decode(&response)
		assert.NoError(t, err)
		assert.Equal(t, expectedToken, response["token"])
	})

	t.Run("dummy login success - moderator", func(t *testing.T) {
		loginReq := struct {
			Role string `json:"role"`
		}{
			Role: "moderator",
		}

		expectedToken := "moderator-token"

		mockTokens.EXPECT().
			CreateToken("moderator", "moderator@mail.ru").
			Return(expectedToken, nil)

		requestBody, _ := json.Marshal(loginReq)
		req := httptest.NewRequest(http.MethodPost, "/dummyLogin", bytes.NewBuffer(requestBody))
		w := httptest.NewRecorder()

		s.PostDummyLogin(w, req)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)

		var response map[string]string
		err := json.NewDecoder(w.Body).Decode(&response)
		assert.NoError(t, err)
		assert.Equal(t, expectedToken, response["token"])
	})

	t.Run("invalid role in request", func(t *testing.T) {
		reqBody := `{"role":"admin"}`
		req := httptest.NewRequest(http.MethodPost, "/dummyLogin", strings.NewReader(reqBody))
		w := httptest.NewRecorder()

		s.PostDummyLogin(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
	})

	t.Run("invalid json in request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/dummyLogin", strings.NewReader(`{`))
		w := httptest.NewRecorder()

		s.PostDummyLogin(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
	})

	t.Run("error creating token", func(t *testing.T) {
		loginReq := struct {
			Role string `json:"role"`
		}{
			Role: "employee",
		}

		mockTokens.EXPECT().
			CreateToken("employee", "employee@mail.ru").
			Return("", errors.New("token error"))

		requestBody, _ := json.Marshal(loginReq)
		req := httptest.NewRequest(http.MethodPost, "/dummyLogin", bytes.NewBuffer(requestBody))
		w := httptest.NewRecorder()

		s.PostDummyLogin(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
	})
}

func TestPostRegister(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockDB := mocks.NewMockRepository(ctrl)
	mockTokens := mocks.NewMockTokenManager(ctrl)

	s := &MyService{
		db:     mockDB,
		tokens: mockTokens,
		logger: logrus.New(),
	}

	t.Run("register success", func(t *testing.T) {
		registerReq := dto.PostRegisterJSONRequestBody{
			Email:    "client@mail.ru",
			Password: "password",
			Role:     "client",
		}

		requestBody, _ := json.Marshal(registerReq)

		gomock.InOrder(
			mockDB.EXPECT().RegisterUser(gomock.Any(), gomock.AssignableToTypeOf(models.User{})).DoAndReturn(
				func(ctx context.Context, u models.User) (models.User, error) {
					return models.User{
						ID:    u.ID,
						Email: u.Email,
						Role:  u.Role,
					}, nil
				},
			),
			mockTokens.EXPECT().CreateToken("client", "client@mail.ru").Return("token-123", nil),
		)

		req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(requestBody))
		w := httptest.NewRecorder()

		s.PostRegister(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var response struct {
			Token string      `json:"token"`
			User  models.User `json:"user"`
		}

		err := json.NewDecoder(w.Body).Decode(&response)
		assert.NoError(t, err)
		assert.Equal(t, "token-123", response.Token)
		assert.Equal(t, "client@mail.ru", response.User.Email)
		assert.Equal(t, "client", response.User.Role)
	})

	t.Run("bad request - invalid json", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(`{`))
		w := httptest.NewRecorder()

		s.PostRegister(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("bad request - missing fields", func(t *testing.T) {
		registerReq := dto.PostRegisterJSONRequestBody{
			Email:    "",
			Password: "1234",
			Role:     "client",
		}

		body, _ := json.Marshal(registerReq)
		req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		s.PostRegister(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("register failed - db error", func(t *testing.T) {
		registerReq := dto.PostRegisterJSONRequestBody{
			Email:    "fail@mail.ru",
			Password: "password",
			Role:     "client",
		}

		body, _ := json.Marshal(registerReq)

		mockDB.EXPECT().RegisterUser(gomock.Any(), gomock.Any()).
			Return(models.User{}, errors.New("db error"))

		req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		s.PostRegister(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("token creation failed", func(t *testing.T) {
		registerReq := dto.PostRegisterJSONRequestBody{
			Email:    "fail2@mail.ru",
			Password: "password",
			Role:     "client",
		}

		body, _ := json.Marshal(registerReq)

		mockDB.EXPECT().RegisterUser(gomock.Any(), gomock.Any()).
			Return(models.User{
				ID:    uuid.New(),
				Email: "fail2@mail.ru",
				Role:  "client",
			}, nil)

		mockTokens.EXPECT().CreateToken("client", "fail2@mail.ru").
			Return("", errors.New("token err"))

		req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		s.PostRegister(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestPostLogin(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockDB := mocks.NewMockRepository(ctrl)
	mockTokens := mocks.NewMockTokenManager(ctrl)

	s := &MyService{
		db:     mockDB,
		tokens: mockTokens,
		logger: logrus.New(),
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)

	t.Run("login success", func(t *testing.T) {
		loginReq := dto.PostLoginJSONRequestBody{
			Email:    "user@mail.ru",
			Password: "password123",
		}

		mockDB.EXPECT().GetUserByEmail("user@mail.ru").Return(models.User{
			Email:    "user@mail.ru",
			Password: string(hashedPassword),
			Role:     "client",
		}, nil)

		mockTokens.EXPECT().CreateToken("client", "user@mail.ru").Return("token-123", nil)

		body, _ := json.Marshal(loginReq)
		req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		s.PostLogin(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]string
		err := json.NewDecoder(w.Body).Decode(&response)
		assert.NoError(t, err)
		assert.Equal(t, "token-123", response["token"])
	})

	t.Run("invalid json", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("{"))
		w := httptest.NewRecorder()

		s.PostLogin(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("missing fields", func(t *testing.T) {
		loginReq := dto.PostLoginJSONRequestBody{
			Email:    "",
			Password: "",
		}
		body, _ := json.Marshal(loginReq)
		req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		s.PostLogin(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("user not found", func(t *testing.T) {
		loginReq := dto.PostLoginJSONRequestBody{
			Email:    "unknown@mail.ru",
			Password: "password",
		}
		mockDB.EXPECT().GetUserByEmail("unknown@mail.ru").
			Return(models.User{}, errors.New("not found"))

		body, _ := json.Marshal(loginReq)
		req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		s.PostLogin(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("wrong password", func(t *testing.T) {
		loginReq := dto.PostLoginJSONRequestBody{
			Email:    "user@mail.ru",
			Password: "wrong-password",
		}

		mockDB.EXPECT().GetUserByEmail("user@mail.ru").Return(models.User{
			Email:    "user@mail.ru",
			Password: string(hashedPassword),
			Role:     "client",
		}, nil)

		body, _ := json.Marshal(loginReq)
		req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		s.PostLogin(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("token generation failed", func(t *testing.T) {
		loginReq := dto.PostLoginJSONRequestBody{
			Email:    "user@mail.ru",
			Password: "password123",
		}

		mockDB.EXPECT().GetUserByEmail("user@mail.ru").Return(models.User{
			Email:    "user@mail.ru",
			Password: string(hashedPassword),
			Role:     "client",
		}, nil)

		mockTokens.EXPECT().CreateToken("client", "user@mail.ru").Return("", errors.New("token error"))

		body, _ := json.Marshal(loginReq)
		req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		s.PostLogin(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestPostPvz(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockDB := mocks.NewMockRepository(ctrl)
	mockTokens := mocks.NewMockTokenManager(ctrl)

	s := &MyService{
		db:     mockDB,
		tokens: mockTokens,
		logger: logrus.New(),
	}

	t.Run("create pvz success", func(t *testing.T) {
		reqBody := dto.PostPvzJSONRequestBody{
			City: "Moscow",
		}

		token := "Bearer valid-token"
		userData := &auth.AuthData{
			Email: "mod@mail.ru",
			Role:  "moderator",
		}

		pvz := models.PVZ{
			ID:                uuid.New(),
			RegistrationDate:  time.Now(),
			City:              "Moscow",
		}

		mockTokens.EXPECT().VerifyToken("Bearer valid-token").Return(userData, nil)
		mockDB.EXPECT().CreatePVZ(gomock.Any(), gomock.Any()).Return(pvz, nil)

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/pvz", bytes.NewBuffer(body))
		req.Header.Set("Authorization", token)
		w := httptest.NewRecorder()

		s.PostPvz(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var response models.PVZ
		err := json.NewDecoder(w.Body).Decode(&response)
		assert.NoError(t, err)
		assert.Equal(t, "Moscow", response.City)
	})

	t.Run("invalid token", func(t *testing.T) {
		mockTokens.EXPECT().VerifyToken("Bearer invalid").Return(&auth.AuthData{}, errors.New("invalid token"))

		req := httptest.NewRequest(http.MethodPost, "/pvz", nil)
		req.Header.Set("Authorization", "Bearer invalid")
		w := httptest.NewRecorder()

		s.PostPvz(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("unauthorized role", func(t *testing.T) {
		mockTokens.EXPECT().VerifyToken("Bearer token").Return(&auth.AuthData{
			Email: "employee@mail.ru",
			Role:  "employee",
		}, nil)

		req := httptest.NewRequest(http.MethodPost, "/pvz", nil)
		req.Header.Set("Authorization", "Bearer token")
		w := httptest.NewRecorder()

		s.PostPvz(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("invalid request body", func(t *testing.T) {
		mockTokens.EXPECT().VerifyToken("Bearer token").Return(&auth.AuthData{
			Email: "mod@mail.ru",
			Role:  "moderator",
		}, nil)

		req := httptest.NewRequest(http.MethodPost, "/pvz", strings.NewReader("{"))
		req.Header.Set("Authorization", "Bearer token")
		w := httptest.NewRecorder()

		s.PostPvz(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("db error", func(t *testing.T) {
		mockTokens.EXPECT().VerifyToken("Bearer token").Return(&auth.AuthData{
			Email: "mod@mail.ru",
			Role:  "moderator",
		}, nil)

		reqBody := dto.PostPvzJSONRequestBody{
			City: "Moscow",
		}
		mockDB.EXPECT().CreatePVZ(gomock.Any(), gomock.Any()).Return(models.PVZ{}, errors.New("db fail"))

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/pvz", bytes.NewBuffer(body))
		req.Header.Set("Authorization", "Bearer token")
		w := httptest.NewRecorder()

		s.PostPvz(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestPostReceptions(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockDB := mocks.NewMockRepository(ctrl)
	mockTokens := mocks.NewMockTokenManager(ctrl)

	s := &MyService{
		db:     mockDB,
		tokens: mockTokens,
		logger: logrus.New(),
	}

	t.Run("create reception success", func(t *testing.T) {
		pvzID := uuid.New()
		expectedReception := models.Reception{
			ID:    uuid.New(),
			PVZID: pvzID,
		}
	
		mockTokens.EXPECT().VerifyToken("Bearer valid-token").Return(&auth.AuthData{
			Email: "employee@mail.ru",
			Role:  "employee",
		}, nil)
	
		mockDB.EXPECT().
			CreateReception(gomock.Any(), gomock.Any()).
			Return(expectedReception, nil)
	
		reqBody := dto.PostReceptionsJSONRequestBody{
			PvzId: pvzID,
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/receptions", bytes.NewBuffer(body))
		req.Header.Set("Authorization", "Bearer valid-token")
		w := httptest.NewRecorder()
	
		s.PostReceptions(w, req)
	
		assert.Equal(t, http.StatusCreated, w.Code)
	
		var response models.Reception
		err := json.NewDecoder(w.Body).Decode(&response)
		assert.NoError(t, err)
		assert.Equal(t, pvzID, response.PVZID)
	})
	

	t.Run("invalid token", func(t *testing.T) {
		mockTokens.EXPECT().VerifyToken("Bearer invalid").Return(nil, errors.New("invalid token"))

		req := httptest.NewRequest(http.MethodPost, "/receptions", nil)
		req.Header.Set("Authorization", "Bearer invalid")
		w := httptest.NewRecorder()

		s.PostReceptions(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("unauthorized role", func(t *testing.T) {
		mockTokens.EXPECT().VerifyToken("Bearer token").Return(&auth.AuthData{
			Email: "mod@mail.ru",
			Role:  "moderator",
		}, nil)

		req := httptest.NewRequest(http.MethodPost, "/receptions", nil)
		req.Header.Set("Authorization", "Bearer token")
		w := httptest.NewRecorder()

		s.PostReceptions(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("invalid request body", func(t *testing.T) {
		mockTokens.EXPECT().VerifyToken("Bearer token").Return(&auth.AuthData{
			Email: "employee@mail.ru",
			Role:  "employee",
		}, nil)

		req := httptest.NewRequest(http.MethodPost, "/receptions", strings.NewReader("{"))
		req.Header.Set("Authorization", "Bearer token")
		w := httptest.NewRecorder()

		s.PostReceptions(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("db error", func(t *testing.T) {
		pvzID := uuid.New()
		reqBody := dto.PostReceptionsJSONRequestBody{
			PvzId: pvzID,
		}

		mockTokens.EXPECT().VerifyToken("Bearer token").Return(&auth.AuthData{
			Email: "employee@mail.ru",
			Role:  "employee",
		}, nil)

		mockDB.EXPECT().
		CreateReception(gomock.Any(), gomock.Any()).
		Return(models.Reception{}, errors.New("some db error"))

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/receptions", bytes.NewBuffer(body))
		req.Header.Set("Authorization", "Bearer token")
		w := httptest.NewRecorder()

		s.PostReceptions(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}


func TestPostProducts(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockDB := mocks.NewMockRepository(ctrl)
	mockTokens := mocks.NewMockTokenManager(ctrl)

	s := &MyService{
		db:     mockDB,
		tokens: mockTokens,
		logger: logrus.New(),
	}

	t.Run("create product success", func(t *testing.T) {
		pvzID := uuid.New()
		productType := "обувь"
		reqBody := dto.PostProductsJSONBody{
			PvzId: pvzID,
			Type:  dto.PostProductsJSONBodyType(productType),
		}
	
		mockTokens.EXPECT().VerifyToken("Bearer valid-token").Return(&auth.AuthData{
			Email: "employee@mail.ru",
			Role:  "employee",
		}, nil)
	
		mockDB.EXPECT().
			AddProducts(gomock.Any(), gomock.AssignableToTypeOf(&models.Product{}), pvzID).
			DoAndReturn(func(_ context.Context, p *models.Product, _ uuid.UUID) (models.Product, error) {
				return *p, nil
			})
	
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/products", bytes.NewBuffer(body))
		req.Header.Set("Authorization", "Bearer valid-token")
		w := httptest.NewRecorder()
	
		s.PostProducts(w, req)
	
		assert.Equal(t, http.StatusCreated, w.Code)
	
		var response models.Product
		err := json.NewDecoder(w.Body).Decode(&response)
		assert.NoError(t, err)
		assert.Equal(t, string(models.ProductTypes[productType]), string(response.Type))
	})

	t.Run("invalid token", func(t *testing.T) {
		mockTokens.EXPECT().VerifyToken("Bearer invalid").Return(nil, errors.New("invalid"))

		req := httptest.NewRequest(http.MethodPost, "/products", nil)
		req.Header.Set("Authorization", "Bearer invalid")
		w := httptest.NewRecorder()

		s.PostProducts(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("unauthorized role", func(t *testing.T) {
		mockTokens.EXPECT().VerifyToken("Bearer token").Return(&auth.AuthData{
			Email: "user@mail.ru",
			Role:  "client",
		}, nil)

		req := httptest.NewRequest(http.MethodPost, "/products", nil)
		req.Header.Set("Authorization", "Bearer token")
		w := httptest.NewRecorder()

		s.PostProducts(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("invalid request body", func(t *testing.T) {
		mockTokens.EXPECT().VerifyToken("Bearer token").Return(&auth.AuthData{
			Email: "employee@mail.ru",
			Role:  "employee",
		}, nil)

		req := httptest.NewRequest(http.MethodPost, "/products", strings.NewReader("{"))
		req.Header.Set("Authorization", "Bearer token")
		w := httptest.NewRecorder()

		s.PostProducts(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("invalid product type", func(t *testing.T) {
		pvzID := uuid.New()
		reqBody := dto.PostProductsJSONBody{
			PvzId: pvzID,
			Type: dto.PostProductsJSONBodyType("INVALID_TYPE"),
		}

		mockTokens.EXPECT().VerifyToken("Bearer token").Return(&auth.AuthData{
			Email: "employee@mail.ru",
			Role:  "employee",
		}, nil)

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/products", bytes.NewBuffer(body))
		req.Header.Set("Authorization", "Bearer token")
		w := httptest.NewRecorder()

		s.PostProducts(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("db error", func(t *testing.T) {
		pvzID := uuid.New()
		productType := "обувь"
		reqBody := dto.PostProductsJSONBody{
			PvzId: pvzID,
			Type: dto.PostProductsJSONBodyType(productType),
		}

		mockTokens.EXPECT().VerifyToken("Bearer token").Return(&auth.AuthData{
			Email: "employee@mail.ru",
			Role:  "employee",
		}, nil)

		mockDB.EXPECT().
			AddProducts(gomock.Any(), gomock.AssignableToTypeOf(&models.Product{}), pvzID).
			Return(models.Product{}, errors.New("db fail"))

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/products", bytes.NewBuffer(body))
		req.Header.Set("Authorization", "Bearer token")
		w := httptest.NewRecorder()

		s.PostProducts(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestPostPvzPvzIdDeleteLastProduct(t *testing.T) {
    t.Run("delete_last_product_success", func(t *testing.T) {
        ctrl := gomock.NewController(t)
        defer ctrl.Finish()

        mockDB := mocks.NewMockRepository(ctrl)
        mockTokens := mocks.NewMockTokenManager(ctrl)

        s := &MyService{
            db:     mockDB,
            tokens: mockTokens,
        }

        pvzID := uuid.New()

        mockTokens.EXPECT().
            VerifyToken("Bearer valid-token").
            Return(&auth.AuthData{
                Email: "employee@mail.ru",
                Role:  "employee",
            }, nil)

        mockDB.EXPECT().
            DeleteLastProduct(gomock.Any(), models.PVZ{ID: pvzID}).
            Return(nil)

        req := httptest.NewRequest(http.MethodPost, "/pvz/"+pvzID.String()+"/delete_last_product", nil)
        req.Header.Set("Authorization", "Bearer valid-token")

        ctx := chi.NewRouteContext()
        ctx.URLParams.Add("pvzId", pvzID.String())
        req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, ctx))

        w := httptest.NewRecorder()

        s.PostPvzPvzIdDeleteLastProduct(w, req, pvzID)

        assert.Equal(t, http.StatusOK, w.Code)
    })

    t.Run("invalid_token", func(t *testing.T) {
        ctrl := gomock.NewController(t)
        defer ctrl.Finish()

        mockDB := mocks.NewMockRepository(ctrl)
        mockTokens := mocks.NewMockTokenManager(ctrl)

        s := &MyService{
            db:     mockDB,
            tokens: mockTokens,
        }

        pvzID := uuid.New()

        mockTokens.EXPECT().
            VerifyToken("Bearer invalid-token").
            Return(nil, errors.New("invalid token"))

        req := httptest.NewRequest(http.MethodPost, "/pvz/"+pvzID.String()+"/delete_last_product", nil)
        req.Header.Set("Authorization", "Bearer invalid-token")

        ctx := chi.NewRouteContext()
        ctx.URLParams.Add("pvzId", pvzID.String())
        req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, ctx))

        w := httptest.NewRecorder()

        s.PostPvzPvzIdDeleteLastProduct(w, req, pvzID)

        assert.Equal(t, http.StatusBadRequest, w.Code)
    })

	t.Run("invalid_uuid_in_path", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
	
		mockDB := mocks.NewMockRepository(ctrl)
		mockTokens := mocks.NewMockTokenManager(ctrl)
	
		s := &MyService{
			db:     mockDB,
			tokens: mockTokens,
		}

		mockTokens.EXPECT().
			VerifyToken("Bearer valid-token").
			Return(&auth.AuthData{
				Email: "employee@mail.ru",
				Role:  "employee",
			}, nil)
	
		req := httptest.NewRequest(http.MethodPost, "/pvz/invalid-uuid/delete_last_product", nil)
		req.Header.Set("Authorization", "Bearer valid-token")
	
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("pvzId", "invalid-uuid") 
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, ctx))
	
		w := httptest.NewRecorder()
	
		s.PostPvzPvzIdDeleteLastProduct(w, req, uuid.Nil)
	
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
	

    t.Run("delete_last_product_error", func(t *testing.T) {
        ctrl := gomock.NewController(t)
        defer ctrl.Finish()

        mockDB := mocks.NewMockRepository(ctrl)
        mockTokens := mocks.NewMockTokenManager(ctrl)

        s := &MyService{
            db:     mockDB,
            tokens: mockTokens,
        }

        pvzID := uuid.New()

        mockTokens.EXPECT().
            VerifyToken("Bearer valid-token").
            Return(&auth.AuthData{
                Email: "employee@mail.ru",
                Role:  "employee",
            }, nil)

        mockDB.EXPECT().
            DeleteLastProduct(gomock.Any(), models.PVZ{ID: pvzID}).
            Return(errors.New("db error"))

        req := httptest.NewRequest(http.MethodPost, "/pvz/"+pvzID.String()+"/delete_last_product", nil)
        req.Header.Set("Authorization", "Bearer valid-token")

        ctx := chi.NewRouteContext()
        ctx.URLParams.Add("pvzId", pvzID.String())
        req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, ctx))

        w := httptest.NewRecorder()
        s.PostPvzPvzIdDeleteLastProduct(w, req, pvzID)

        assert.Equal(t, http.StatusBadRequest, w.Code)
    })
}

func TestPostPvzPvzIdCloseLastReception(t *testing.T) {
	t.Run("close_last_reception_success", func(t *testing.T) {
        ctrl := gomock.NewController(t)
        defer ctrl.Finish()

        mockDB := mocks.NewMockRepository(ctrl)
        mockTokens := mocks.NewMockTokenManager(ctrl)

        s := &MyService{
            db:     mockDB,
            tokens: mockTokens,
        }

        pvzID := uuid.New()

        mockTokens.EXPECT().
            VerifyToken("Bearer valid-token").
            Return(&auth.AuthData{
                Email: "employee@mail.ru",
                Role:  "employee", 
            }, nil)

        closedReception := models.Reception{
            ID: uuid.New(), 
            Status: "closed",
        }

        mockDB.EXPECT().
            CloseLastReception(gomock.Any(), gomock.Eq(models.PVZ{ID: pvzID})).
            Return(closedReception, nil)

        req := httptest.NewRequest(http.MethodPost, "/pvz/"+pvzID.String()+"/close_last_reception", nil)
        req.Header.Set("Authorization", "Bearer valid-token")

        ctx := chi.NewRouteContext()
        ctx.URLParams.Add("pvzId", pvzID.String())
        req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, ctx))

        w := httptest.NewRecorder()

        s.PostPvzPvzIdCloseLastReception(w, req, pvzID)

        assert.Equal(t, http.StatusOK, w.Code)
        
        var responseReception models.Reception
        err := json.Unmarshal(w.Body.Bytes(), &responseReception)
        assert.NoError(t, err)
        assert.Equal(t, closedReception, responseReception)
    })

    t.Run("invalid_token", func(t *testing.T) {
        ctrl := gomock.NewController(t)
        defer ctrl.Finish()

        mockDB := mocks.NewMockRepository(ctrl)
        mockTokens := mocks.NewMockTokenManager(ctrl)

        s := &MyService{
            db:     mockDB,
            tokens: mockTokens,
        }

        mockTokens.EXPECT().
            VerifyToken("Bearer invalid-token").
            Return(nil, fmt.Errorf("invalid token"))

        req := httptest.NewRequest(http.MethodPost, "/pvz/{pvzId}/close_last_reception", nil)
        req.Header.Set("Authorization", "Bearer invalid-token")

        w := httptest.NewRecorder()

        s.PostPvzPvzIdCloseLastReception(w, req, uuid.New())

        assert.Equal(t, http.StatusBadRequest, w.Code)
        assert.Contains(t, w.Body.String(), "Неверный запрос")
    })

    t.Run("db_error", func(t *testing.T) {
        ctrl := gomock.NewController(t)
        defer ctrl.Finish()

        mockDB := mocks.NewMockRepository(ctrl)
        mockTokens := mocks.NewMockTokenManager(ctrl)

        s := &MyService{
            db:     mockDB,
            tokens: mockTokens,
        }

        pvzID := uuid.New()

        mockTokens.EXPECT().
            VerifyToken("Bearer valid-token").
            Return(&auth.AuthData{
                Email: "employee@mail.ru",
                Role:  "employee", 
            }, nil)

        mockDB.EXPECT().
            CloseLastReception(gomock.Any(), gomock.Eq(models.PVZ{ID: pvzID})).
            Return(models.Reception{}, fmt.Errorf("reception already closed"))

        req := httptest.NewRequest(http.MethodPost, "/pvz/"+pvzID.String()+"/close_last_reception", nil)
        req.Header.Set("Authorization", "Bearer valid-token")

        ctx := chi.NewRouteContext()
        ctx.URLParams.Add("pvzId", pvzID.String())
        req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, ctx))

        w := httptest.NewRecorder()

        s.PostPvzPvzIdCloseLastReception(w, req, pvzID)

        assert.Equal(t, http.StatusBadRequest, w.Code)
        assert.Contains(t, w.Body.String(), "Неверный запрос или приемка уже закрыта")
    })
}

func TestGetPvz(t *testing.T) {

	t.Run("get_pvz_info_success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
	
		mockDB := mocks.NewMockRepository(ctrl)
		mockTokens := mocks.NewMockTokenManager(ctrl)
	
		s := &MyService{
			db:     mockDB,
			tokens: mockTokens,
		}
	
		mockTokens.EXPECT().
			VerifyToken("Bearer valid-token").
			Return(&auth.AuthData{
				Email: "manager@mail.ru",
				Role:  "moderator", 
			}, nil)
	
		startDate := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
		endDate := time.Date(2025, 4, 16, 0, 0, 0, 0, time.UTC)
		page := 1
		limit := 10
	
		fixedTime := time.Date(2023, 5, 15, 10, 0, 0, 0, time.UTC)
		pvzId1 := uuid.MustParse("11111111-1111-1111-1111-111111111111")
		pvzId2 := uuid.MustParse("22222222-2222-2222-2222-222222222222")
		recId1 := uuid.MustParse("33333333-3333-3333-3333-333333333333")
		recId2 := uuid.MustParse("44444444-4444-4444-4444-444444444444")
		prodId1 := uuid.MustParse("55555555-5555-5555-5555-555555555555")
		prodId2 := uuid.MustParse("66666666-6666-6666-6666-666666666666")

		expectedPVZs := models.PVZWithReceptions{
			PVZs: []models.PVZReceptions{
				{
					PVZ: models.PVZ{
						ID:               pvzId1,
						RegistrationDate: fixedTime,
						City:             "Moscow",
						LastReceptionID:  recId1,
					},
					Receptions: []models.ReceptionProducts{
						{
							Reception: models.Reception{
								ID:         recId1,
								ReceivedAt: fixedTime,
								PVZID:      pvzId1,
								Status:     "closed",
							},
							Products: []models.Product{
								{
									ID:          prodId1,
									ReceivedAt:  fixedTime,
									Type:        "Type1",
									ReceptionID: recId1,
								},
							},
						},
					},
				},
				{
					PVZ: models.PVZ{
						ID:               pvzId2,
						RegistrationDate: fixedTime,
						City:             "Saint Petersburg",
						LastReceptionID:  recId2,
					},
					Receptions: []models.ReceptionProducts{
						{
							Reception: models.Reception{
								ID:         recId2,
								ReceivedAt: fixedTime,
								PVZID:      pvzId2,
								Status:     "active",
							},
							Products: []models.Product{
								{
									ID:          prodId2,
									ReceivedAt:  fixedTime,
									Type:        "Type2",
									ReceptionID: recId2,
								},
							},
						},
					},
				},
			},
			Total: 2,
			Page:  page,
			Limit: limit,
		}

		mockDB.EXPECT().
			GetPVZInfo(gomock.Any(), startDate, endDate, page, limit).
			Return(expectedPVZs, nil)

		rawURL := fmt.Sprintf("/pvz?startDate=%s&endDate=%s&page=%d&limit=%d",
			startDate.Format(time.RFC3339),
			endDate.Format(time.RFC3339),
			page,
			limit)
		
		req := httptest.NewRequest(http.MethodGet, rawURL, nil)
		req.Header.Set("Authorization", "Bearer valid-token")
	
		w := httptest.NewRecorder()
	
		params := dto.GetPvzParams{}
	
		s.GetPvz(w, req, params)
	
		assert.Equal(t, http.StatusOK, w.Code)

		var responsePVZs models.PVZWithReceptions
		err := json.Unmarshal(w.Body.Bytes(), &responsePVZs)
		assert.NoError(t, err)
		
		assert.Equal(t, expectedPVZs.Total, responsePVZs.Total)
		assert.Equal(t, expectedPVZs.Page, responsePVZs.Page)
		assert.Equal(t, expectedPVZs.Limit, responsePVZs.Limit)
		assert.Equal(t, len(expectedPVZs.PVZs), len(responsePVZs.PVZs))
		
		for i, pvzRec := range responsePVZs.PVZs {

			assert.Equal(t, expectedPVZs.PVZs[i].PVZ.ID, pvzRec.PVZ.ID)
			assert.Equal(t, expectedPVZs.PVZs[i].PVZ.City, pvzRec.PVZ.City)
			assert.Equal(t, expectedPVZs.PVZs[i].PVZ.LastReceptionID, pvzRec.PVZ.LastReceptionID)
			assert.Equal(t, 
				expectedPVZs.PVZs[i].PVZ.RegistrationDate.Format(time.RFC3339),
				pvzRec.PVZ.RegistrationDate.Format(time.RFC3339))
			
			assert.Equal(t, len(expectedPVZs.PVZs[i].Receptions), len(pvzRec.Receptions))
			for j, recProd := range pvzRec.Receptions {

				assert.Equal(t, expectedPVZs.PVZs[i].Receptions[j].Reception.ID, recProd.Reception.ID)
				assert.Equal(t, expectedPVZs.PVZs[i].Receptions[j].Reception.PVZID, recProd.Reception.PVZID)
				assert.Equal(t, expectedPVZs.PVZs[i].Receptions[j].Reception.Status, recProd.Reception.Status)
				assert.Equal(t,
					expectedPVZs.PVZs[i].Receptions[j].Reception.ReceivedAt.Format(time.RFC3339),
					recProd.Reception.ReceivedAt.Format(time.RFC3339))
				
				assert.Equal(t, len(expectedPVZs.PVZs[i].Receptions[j].Products), len(recProd.Products))
				for k, prod := range recProd.Products {
					assert.Equal(t, expectedPVZs.PVZs[i].Receptions[j].Products[k].ID, prod.ID)
					assert.Equal(t, expectedPVZs.PVZs[i].Receptions[j].Products[k].Type, prod.Type)
					assert.Equal(t, expectedPVZs.PVZs[i].Receptions[j].Products[k].ReceptionID, prod.ReceptionID)
					assert.Equal(t,
						expectedPVZs.PVZs[i].Receptions[j].Products[k].ReceivedAt.Format(time.RFC3339),
						prod.ReceivedAt.Format(time.RFC3339))
				}
			}
		}
	})
    t.Run("invalid_token", func(t *testing.T) {
        ctrl := gomock.NewController(t)
        defer ctrl.Finish()

        mockDB := mocks.NewMockRepository(ctrl)
        mockTokens := mocks.NewMockTokenManager(ctrl)

        s := &MyService{
            db:     mockDB,
            tokens: mockTokens,
        }

        mockTokens.EXPECT().
            VerifyToken("Bearer invalid-token").
            Return(nil, fmt.Errorf("invalid token"))

        req := httptest.NewRequest(http.MethodGet, "/pvz", nil)
        req.Header.Set("Authorization", "Bearer invalid-token")

        w := httptest.NewRecorder()

        params := dto.GetPvzParams{}
        s.GetPvz(w, req, params)

        assert.Equal(t, http.StatusBadRequest, w.Code)
        assert.Contains(t, w.Body.String(), "Неверный запрос")
    })
    
    t.Run("invalid_role", func(t *testing.T) {
        ctrl := gomock.NewController(t)
        defer ctrl.Finish()

        mockDB := mocks.NewMockRepository(ctrl)
        mockTokens := mocks.NewMockTokenManager(ctrl)

        s := &MyService{
            db:     mockDB,
            tokens: mockTokens,
        }

        mockTokens.EXPECT().
            VerifyToken("Bearer valid-token").
            Return(&auth.AuthData{
                Email: "customer@mail.ru",
                Role:  "customer", 
            }, nil)

        req := httptest.NewRequest(http.MethodGet, "/pvz", nil)
        req.Header.Set("Authorization", "Bearer valid-token")

        w := httptest.NewRecorder()

        params := dto.GetPvzParams{}
        s.GetPvz(w, req, params)

        assert.Equal(t, http.StatusForbidden, w.Code)
        assert.Contains(t, w.Body.String(), "Доступ запрещён")
    })

    t.Run("invalid_date_format", func(t *testing.T) {
        ctrl := gomock.NewController(t)
        defer ctrl.Finish()

        mockDB := mocks.NewMockRepository(ctrl)
        mockTokens := mocks.NewMockTokenManager(ctrl)

        s := &MyService{
            db:     mockDB,
            tokens: mockTokens,
        }

        mockTokens.EXPECT().
            VerifyToken("Bearer valid-token").
            Return(&auth.AuthData{
                Email: "manager@mail.ru",
                Role:  "moderator",
            }, nil)

        req := httptest.NewRequest(http.MethodGet, "/pvz?startDate=01-01-2023&endDate=31-12-2023", nil)
        req.Header.Set("Authorization", "Bearer valid-token")

        w := httptest.NewRecorder()

        params := dto.GetPvzParams{}
        s.GetPvz(w, req, params)

        assert.Equal(t, http.StatusBadRequest, w.Code)
        assert.Contains(t, w.Body.String(), "Неверный запрос")
    })

    t.Run("invalid_page_parameter", func(t *testing.T) {
        ctrl := gomock.NewController(t)
        defer ctrl.Finish()

        mockDB := mocks.NewMockRepository(ctrl)
        mockTokens := mocks.NewMockTokenManager(ctrl)

        s := &MyService{
            db:     mockDB,
            tokens: mockTokens,
        }

        mockTokens.EXPECT().
            VerifyToken("Bearer valid-token").
            Return(&auth.AuthData{
                Email: "manager@mail.ru",
                Role:  "moderator",
            }, nil)

        req := httptest.NewRequest(http.MethodGet, "/pvz?page=invalid", nil)
        req.Header.Set("Authorization", "Bearer valid-token")

        w := httptest.NewRecorder()

        params := dto.GetPvzParams{}
        s.GetPvz(w, req, params)

        assert.Equal(t, http.StatusBadRequest, w.Code)
        assert.Contains(t, w.Body.String(), "Неверный запрос")
    })

    t.Run("invalid_limit_parameter", func(t *testing.T) {
        ctrl := gomock.NewController(t)
        defer ctrl.Finish()

        mockDB := mocks.NewMockRepository(ctrl)
        mockTokens := mocks.NewMockTokenManager(ctrl)

        s := &MyService{
            db:     mockDB,
            tokens: mockTokens,
        }

        mockTokens.EXPECT().
            VerifyToken("Bearer valid-token").
            Return(&auth.AuthData{
                Email: "manager@mail.ru",
                Role:  "moderator",
            }, nil)

        req := httptest.NewRequest(http.MethodGet, "/pvz?limit=50", nil)
        req.Header.Set("Authorization", "Bearer valid-token")

        w := httptest.NewRecorder()

        params := dto.GetPvzParams{}
        s.GetPvz(w, req, params)

        assert.Equal(t, http.StatusBadRequest, w.Code)
        assert.Contains(t, w.Body.String(), "Неверный запрос")
    })
}