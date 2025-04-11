package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/basedalex/avito-backend-2025-spring/internal/auth"
	"github.com/basedalex/avito-backend-2025-spring/internal/mocks"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestNewService(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockDB := mocks.NewMockRepository(ctrl)

	service := NewService(mockDB)

	assert.NotNil(t, service)
	assert.Equal(t, mockDB, service.db)

	_, ok := service.tokens.(JWTTokenManager)
	assert.True(t, ok, "tokens must be JWTTokenManager")
}

func TestDummyLoginHandler_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockDB := mocks.NewMockRepository(ctrl)

	mockTokens := mocks.NewMockTokenManager(ctrl)

	s := &MyService{
		db: mockDB,
		tokens: mockTokens,
	}

	t.Run("Auth return token", func(t *testing.T) {
		authReq := struct {
			Role    string
		}{
			Role:    "client",
		}

		expectedToken := "dummy-token"
		mockTokens.EXPECT().CreateToken(authReq.Role, "client@mail.ru").Return(expectedToken, nil)

		requestBody, _ := json.Marshal(authReq)
		req := httptest.NewRequest(http.MethodPost, "/api/dummyLogin", bytes.NewBuffer(requestBody))

		w := httptest.NewRecorder()
		s.DummyLoginHandler(w, req)
		assert.Equal(t, http.StatusOK, w.Result().StatusCode)

		var response map[string]string
        err := json.NewDecoder(w.Body).Decode(&response)
        assert.NoError(t, err)
        assert.Equal(t, expectedToken, response["token"])
	})

}

func TestDummyLoginHandler_InvalidRole(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockTokenManager := mocks.NewMockTokenManager(ctrl)

	s := &MyService{
		tokens: mockTokenManager,
	}

	body := map[string]string{
		"role": "admin", 
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/dummyLogin", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	s.DummyLoginHandler(rec, req)

	res := rec.Result()
	defer res.Body.Close()

	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
}

func TestDummyLoginHandler_InvalidJSON(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockTokenManager := mocks.NewMockTokenManager(ctrl)

	s := &MyService{
		tokens: mockTokenManager,
	}

	req := httptest.NewRequest(http.MethodPost, "/api/dummyLogin", bytes.NewBufferString("invalid-json"))
	rec := httptest.NewRecorder()

	s.DummyLoginHandler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestDummyLoginHandler_CreateTokenError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockTokenManager := mocks.NewMockTokenManager(ctrl)
	mockTokenManager.EXPECT().CreateToken("client", "client@mail.ru").Return("", errors.New("failed to create token")).Times(1)

	s := &MyService{
		tokens: mockTokenManager,
	}

	body := map[string]string{
		"role": "client",
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/dummy-login", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	s.DummyLoginHandler(rec, req)

	res := rec.Result()
	defer res.Body.Close()

	assert.Equal(t, http.StatusInternalServerError, res.StatusCode)
}

func TestRegisterUserHandler(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockDB := mocks.NewMockRepository(ctrl)

	mockTokens := mocks.NewMockTokenManager(ctrl)

	s := &MyService{
		db: mockDB,
		tokens: mockTokens,
	}

	t.Run(("register success"), func(t *testing.T) {
		registerReq := struct {
			Role    	string
			Email    	string
			Password    string
		}{	
			Role:    "client",
			Email:    "client@mail.ru",
			Password: "password",
		}
		expectedToken := "dummy-token"
		mockTokens.EXPECT().CreateToken(registerReq.Role, "client@mail.ru").Return(expectedToken, nil)
		mockDB.EXPECT().RegisterUser().Return(nil)

		requestBody, _ := json.Marshal(registerReq)
		req := httptest.NewRequest(http.MethodPost, "/api/register", bytes.NewBuffer(requestBody))

		w := httptest.NewRecorder()
		s.RegisterUserHandler(w, req)
		assert.Equal(t, http.StatusCreated, w.Result().StatusCode)

		var response map[string]string
        err := json.NewDecoder(w.Body).Decode(&response)
        assert.NoError(t, err)
        assert.Equal(t, expectedToken, response["token"])
	})
	t.Run(("register email role"), func(t *testing.T) {
		registerReq := struct {
			Role    	string
			Email    	string
			Password    string
		}{	
			Role:    	"moderator",
			Email:    "",
			Password: "password",
		}
		requestBody, _ := json.Marshal(registerReq)
		req := httptest.NewRequest(http.MethodPost, "/api/register", bytes.NewBuffer(requestBody))

		w := httptest.NewRecorder()
		s.RegisterUserHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)

	})

}


func TestLoginUserHandler(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockDB := mocks.NewMockRepository(ctrl)
	mockTokens := mocks.NewMockTokenManager(ctrl)

	s := &MyService{
		db: mockDB,
		tokens: mockTokens,
	}

	t.Run(("login success"), func(t *testing.T) {
		loginReq := struct {
			Email    	string	`json:"email"`
			Password    string	`json:"password"`
		}{	
			Email:    "client@mail.ru",
			Password: "password",
		}
		expectedToken := "dummy-token"
		mockTokens.EXPECT().CreateToken("client", "client@mail.ru").Return(expectedToken, nil)
		mockDB.EXPECT().LoginUser().Return("client", nil)

		requestBody, _ := json.Marshal(loginReq)
		req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewBuffer(requestBody))

		w := httptest.NewRecorder()
		s.LoginUserHandler(w, req)
		assert.Equal(t, http.StatusOK, w.Result().StatusCode)

		var response map[string]string
        err := json.NewDecoder(w.Body).Decode(&response)
        assert.NoError(t, err)
        assert.Equal(t, expectedToken, response["token"])
	})
}

func TestCreatePVZHandler(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockDB := mocks.NewMockRepository(ctrl)
	mockTokens := mocks.NewMockTokenManager(ctrl)

	s := &MyService{
		db: mockDB,
		tokens: mockTokens,
	}

	t.Run(("PVZ success"), func(t *testing.T) {
		createReq := struct {
			City    	string	`json:"city"`
		}{
			City:    "Moscow",
		}
		expectedAuthData := &auth.AuthData{
			Role: "moderator",
		}
		
		mockTokens.EXPECT().VerifyToken("dummy-token").Return(expectedAuthData, nil)
		mockDB.EXPECT().CreatePVZ(createReq.City).Return(nil)

		requestBody, _ := json.Marshal(createReq)
		req := httptest.NewRequest(http.MethodPost, "/api/pvz", bytes.NewBuffer(requestBody))
		req.Header.Set("Authorization", "dummy-token")
		w := httptest.NewRecorder()
		s.CreatePVZHandler(w, req)
		assert.Equal(t, http.StatusCreated, w.Result().StatusCode)

		var response map[string]string
        err := json.NewDecoder(w.Body).Decode(&response)
        assert.NoError(t, err)
	})

	t.Run(("PVZ success"), func(t *testing.T) {
		createReq := struct {
			City    	string	`json:"city"`
		}{
			City:    "Moscow",
		}
		expectedAuthData := &auth.AuthData{
			Role: "moderator",
		}
		
		mockTokens.EXPECT().VerifyToken("dummy-token").Return(expectedAuthData, nil)
		mockDB.EXPECT().CreatePVZ(createReq.City).Return(nil)

		requestBody, _ := json.Marshal(createReq)
		req := httptest.NewRequest(http.MethodPost, "/api/pvz", bytes.NewBuffer(requestBody))
		req.Header.Set("Authorization", "dummy-token")
		w := httptest.NewRecorder()
		s.CreatePVZHandler(w, req)
		assert.Equal(t, http.StatusCreated, w.Result().StatusCode)

		var response map[string]string
        err := json.NewDecoder(w.Body).Decode(&response)
        assert.NoError(t, err)
	})
	t.Run("forbidden if role is not moderator", func(t *testing.T) {
		mockTokens.EXPECT().VerifyToken("dummy-token").Return(&auth.AuthData{
			Role: "client",
		}, nil)
	
		req := httptest.NewRequest(http.MethodPost, "/api/pvz", nil)
		req.Header.Set("Authorization", "dummy-token")
	
		w := httptest.NewRecorder()
		s.CreatePVZHandler(w, req)
	
		assert.Equal(t, http.StatusForbidden, w.Result().StatusCode)
	
		body, _ := io.ReadAll(w.Body)
		assert.Contains(t, string(body), "Доступ запрещён")
	})
}