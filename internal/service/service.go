package service

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/basedalex/avito-backend-2025-spring/internal/auth"
	"github.com/basedalex/avito-backend-2025-spring/internal/config"
	"github.com/basedalex/avito-backend-2025-spring/internal/db"

	"github.com/sirupsen/logrus"
)

//go:generate mockgen -source=service.go -destination=../mocks/mock_service.go -package=mocks
type Service interface {
	DummyLoginHandler(w http.ResponseWriter, r *http.Request)
	RegisterUserHandler(w http.ResponseWriter, r *http.Request)
	LoginUserHandler(w http.ResponseWriter, r *http.Request)
	CreatePVZHandler(w http.ResponseWriter, r *http.Request)
}


type MyService struct {
	db db.Repository
	cfg *config.Config
	logger logrus.Logger
	tokens TokenManager
}


type TokenManager interface {
	CreateToken(role, email string) (string, error)
	VerifyToken(tokenString string) (*auth.AuthData, error)
}

type JWTTokenManager struct{}

func (j JWTTokenManager) CreateToken(role, email string) (string, error) {
	return auth.CreateToken(role, email) 
}

func (j JWTTokenManager) VerifyToken(tokenString string) (*auth.AuthData, error) {
	return auth.VerifyToken(tokenString)
}

// (POST /api/dummyLogin)
func (s *MyService) DummyLoginHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || (req.Role != "client" && req.Role != "moderator") {
		http.Error(w, "Invalid role", http.StatusBadRequest)
		return
	}

	var email string
	
	if req.Role == "client" {
		email = "client@mail.ru"
	} else {
		email = "moderator@mail.ru"
	}
	

	token, err := s.tokens.CreateToken(req.Role, email)
	if err != nil {
		http.Error(w, "Failed to create token", http.StatusInternalServerError)
		return
	}

	writeResponse(w, http.StatusOK, map[string]string{"token": token})
}

// (POST /api/register)
func (s *MyService) RegisterUserHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string 	`json:"email"`
		Password string `json:"password"`
		Role string 	`json:"role"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.Password == "" || req.Role == "" {
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}

	if err := s.db.RegisterUser(); err != nil {
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}

	token, err := s.tokens.CreateToken(req.Role, req.Email)
	if err != nil {
		http.Error(w, "Failed to create token", http.StatusInternalServerError)
		return
	}

	writeResponse(w, http.StatusCreated, map[string]string{"token": token})
}

// (POST /api/login)
func (s *MyService) LoginUserHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string 	`json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" || req.Password == "" {
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}

	role, err := s.db.LoginUser()
	if err != nil {
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}

	token, err := s.tokens.CreateToken(role, req.Email)
	if err != nil {
		http.Error(w, "Failed to create token", http.StatusInternalServerError)
		return
	}

	writeResponse(w, http.StatusOK, map[string]string{"token": token})
}

// POST /api/pvz
func (s *MyService) CreatePVZHandler(w http.ResponseWriter, r *http.Request) {
	data, err := s.tokens.VerifyToken(r.Header.Get("Authorization"))
	if err != nil {
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}
	if data.Role != "moderator" { 
		http.Error(w, "Доступ запрещён", http.StatusForbidden)
		return
	}
	var req struct {
		City string `json:"city"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}
	if err = s.db.CreatePVZ(req.City); err != nil {
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}
	writeResponse(w, http.StatusCreated, nil)
}

type HTTPResponse struct {
	Data  any    `json:"data,omitempty"`
	Error string `json:"error,omitempty"`
}

func writeResponse(w http.ResponseWriter, statusCode int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	err := json.NewEncoder(w).Encode(data)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func NewService(db db.Repository) *MyService {
	return &MyService{
		db: db,
		tokens: JWTTokenManager{},
	}
}