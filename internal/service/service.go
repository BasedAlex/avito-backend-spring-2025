package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/basedalex/avito-backend-2025-spring/internal/auth"
	"github.com/basedalex/avito-backend-2025-spring/internal/db"
	"github.com/basedalex/avito-backend-2025-spring/internal/db/models"
	dto "github.com/basedalex/avito-backend-2025-spring/internal/generated"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

//go:generate mockgen -source=service.go -destination=../mocks/mock_service.go -package=mocks
type Service interface {
	// Получение тестового токена
	// (POST /dummyLogin)
	PostDummyLogin(w http.ResponseWriter, r *http.Request)
	// Авторизация пользователя
	// (POST /login)
	PostLogin(w http.ResponseWriter, r *http.Request)
	// Добавление товара в текущую приемку (только для сотрудников ПВЗ)
	// (POST /products)
	PostProducts(w http.ResponseWriter, r *http.Request)
	// Получение списка ПВЗ с фильтрацией по дате приемки и пагинацией
	// (GET /pvz)
	GetPvz(w http.ResponseWriter, r *http.Request, params dto.GetPvzParams)
	// Создание ПВЗ (только для модераторов)
	// (POST /pvz)
	PostPvz(w http.ResponseWriter, r *http.Request)
	// Закрытие последней открытой приемки товаров в рамках ПВЗ
	// (POST /pvz/{pvzId}/close_last_reception)
	PostPvzPvzIdCloseLastReception(w http.ResponseWriter, r *http.Request, pvzId uuid.UUID)
	// Удаление последнего добавленного товара из текущей приемки (LIFO, только для сотрудников ПВЗ)
	// (POST /pvz/{pvzId}/delete_last_product)
	PostPvzPvzIdDeleteLastProduct(w http.ResponseWriter, r *http.Request, pvzId uuid.UUID)
	// Создание новой приемки товаров (только для сотрудников ПВЗ)
	// (POST /receptions)
	PostReceptions(w http.ResponseWriter, r *http.Request)
	// Регистрация пользователя
	// (POST /register)
	PostRegister(w http.ResponseWriter, r *http.Request)
}

type MyService struct {
	db db.Repository
	// cfg *config.Config
	logger *logrus.Logger
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
func (s *MyService) PostDummyLogin(w http.ResponseWriter, r *http.Request) {
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
func (s *MyService) PostRegister(w http.ResponseWriter, r *http.Request) {
	var reqUser models.User

	if err := json.NewDecoder(r.Body).Decode(&reqUser); err != nil {
		s.logger.Error("Failed to decode request body", err)
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}

	if reqUser.Email == "" || reqUser.Password == "" || reqUser.Role == "" {
		s.logger.Error("Invalid request body", reqUser)
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(reqUser.Password), bcrypt.DefaultCost)
	if err != nil {
		s.logger.Error("Couldn't generate hashed password", err)
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}

	reqUser.ID = uuid.New()
	reqUser.Password = string(hashedPassword)

	if err := s.db.RegisterUser(r.Context(), reqUser); err != nil {
		s.logger.Error("Error registering new user", err)
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}

	token, err := s.tokens.CreateToken(reqUser.Role, reqUser.Email)
	if err != nil {
		s.logger.Error("Couldn't create token", err)
		http.Error(w, "Failed to create token", http.StatusInternalServerError)
		return
	}

	writeResponse(w, http.StatusCreated, map[string]string{"token": token})
}

// (POST /api/login)
func (s *MyService) PostLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string 	`json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" || req.Password == "" {
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}
	
	user, err := s.db.GetUserByEmail(req.Email)
	if err != nil {
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password))
	if err != nil {
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}

	token, err := s.tokens.CreateToken(user.Role, req.Email)
	if err != nil {
		http.Error(w, "Failed to create token", http.StatusInternalServerError)
		return
	}

	writeResponse(w, http.StatusOK, map[string]string{"token": token})
}

// POST /api/pvz
func (s *MyService) PostPvz(w http.ResponseWriter, r *http.Request) {
	data, err := s.tokens.VerifyToken(r.Header.Get("Authorization"))
	if err != nil {
		s.logger.Error("Failed to verify token", err)
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}
	if data.Role != "moderator" { 
		s.logger.Error("role is not moderator", data.Role)
		http.Error(w, "Доступ запрещён", http.StatusForbidden)
		return
	}
	var pvz models.PVZ

	if err := json.NewDecoder(r.Body).Decode(&pvz); err != nil {
		s.logger.Error("Failed to decode request body", err)
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}
	pvz.ID = uuid.New()
	pvz.RegistrationDate = time.Now().UTC()
	if err = s.db.CreatePVZ(r.Context(), pvz); err != nil {
		s.logger.Error("Failed to create pvz", err)
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}
	writeResponse(w, http.StatusCreated, nil)
}

// POST /receptions
func (s *MyService) PostReceptions(w http.ResponseWriter, r *http.Request) {
	data, err := s.tokens.VerifyToken(r.Header.Get("Authorization"))
	if err != nil {
		s.logger.Error("Failed to verify token", err)
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}
	if data.Role != "client" { 
		s.logger.Error("role is not client", data.Role)
		http.Error(w, "Доступ запрещён", http.StatusForbidden)
		return
	}

	var req struct {
		PVZID string `json:"pvz_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Error("Failed to decode request body", err)
		http.Error(w, "Неверный запрос или есть незакрытая приемка", http.StatusBadRequest)
		return
	}

	PVZUUID, err  := uuid.Parse(req.PVZID)
	if err != nil {
		s.logger.Error("Failed to parse UUID", err)
		http.Error(w, "Неверный запрос или есть незакрытая приемка", http.StatusBadRequest)
		return
	}


	status, err := s.db.CheckReceptionStatus(r.Context(), PVZUUID); 
	if err != nil || status == "in_progress" {
		s.logger.Error("Failed to check reception status", err)
		http.Error(w, "Неверный запрос или есть незакрытая приемка", http.StatusBadRequest)
	}

	s.logger.Infof("status: %v", status)

	createReceptionRequest := &models.Reception{
		ID: uuid.New(),
		PVZID: PVZUUID,
		ReceivedAt: time.Now().UTC(),
		Status: status,
	}


	if err = s.db.CreateReception(r.Context(), createReceptionRequest); err != nil {
		s.logger.Warn("Failed to create reception", err)
		http.Error(w, "Неверный запрос или есть незакрытая приемка", http.StatusBadRequest)
		return
	}
	s.logger.Info("Reception created", createReceptionRequest)
	writeResponse(w, http.StatusCreated, nil)
}

// POST /products
func (s *MyService) PostProducts(w http.ResponseWriter, r *http.Request) {
	data, err := s.tokens.VerifyToken(r.Header.Get("Authorization"))
	if err != nil {
		s.logger.Error("Failed to verify token", err)
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}
	if data.Role != "client" { 
		s.logger.Error("role is not client", data.Role)
		http.Error(w, "Доступ запрещён", http.StatusForbidden)
		return
	}

	var req dto.PostProductsJSONBody

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Error("Failed to decode request body", err)
		http.Error(w, "Неверный запрос или нет активной приемки", http.StatusBadRequest)
		return
	}

	productType, ok := models.ProductTypes[strings.ToLower(string(req.Type))]
	if !ok {
		s.logger.Error("Invalid product type", req.Type)
		http.Error(w, "Неверный запрос или нет активной приемки", http.StatusBadRequest)
		return
	}

	status, err := s.db.CheckReceptionStatus(r.Context(), req.PvzId); 
	if err != nil || status != "in_progress" {
		s.logger.Error("Invalid status ", status, " or error getting reception", err)
		http.Error(w, "Неверный запрос или нет активной приемки", http.StatusBadRequest)
	}

	s.logger.Infof("status: %v", status)

	product := &models.Product{
		ID: uuid.New(),
		ReceivedAt: time.Now().UTC(),
		Type: productType,
	}
	
	s.logger.Infof("request: %+v", req)

	if err = s.db.AddProducts(r.Context(), product, req.PvzId); err != nil {
		s.logger.Error("Error adding product", err)
		http.Error(w, "Неверный запрос или нет активной приемки", http.StatusBadRequest)
		return
	}
	s.logger.Info("product added ", product)
	
	writeResponse(w, http.StatusCreated, nil)
}


// POST /api/pvz/{pvzId}/delete_last_product
func (s *MyService) PostPvzPvzIdDeleteLastProduct(w http.ResponseWriter, r *http.Request, pvzId uuid.UUID) {
	data, err := s.tokens.VerifyToken(r.Header.Get("Authorization"))
	if err != nil {
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}
	if data.Role != "client" { 
		http.Error(w, "Доступ запрещён", http.StatusForbidden)
		return
	}

	pvzID, err := parseUUID(r)
	if err != nil {
		http.Error(w, "Неверный запрос, нет активной приемки или нет товаров для удаления", http.StatusBadRequest)
		return
	}

	pvz := models.PVZ{
		ID: pvzID,
	}

	if err = s.db.DeleteLastProduct(r.Context(), pvz); err != nil {
		http.Error(w, "Неверный запрос, нет активной приемки или нет товаров для удаления", http.StatusBadRequest)
		return
	}
	
	writeResponse(w, http.StatusOK, nil)
}
func parseUUID(r *http.Request) (uuid.UUID, error) {
	pvzStringID := chi.URLParam(r, "pvzId")
	if pvzStringID == "" {
		return uuid.UUID{}, errors.New("pvzId is empty")
	}
	pvzID, err := uuid.Parse(pvzStringID)
	if err != nil {
		return uuid.UUID{}, err
	}
	return pvzID, nil
}


// POST /api/pvz/{pvzId}/close_last_reception
func (s *MyService) PostPvzPvzIdCloseLastReception(w http.ResponseWriter, r *http.Request, pvzId uuid.UUID) {
	data, err := s.tokens.VerifyToken(r.Header.Get("Authorization"))
	if err != nil {
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}
	if data.Role != "client" { 
		http.Error(w, "Доступ запрещён", http.StatusForbidden)
		return
	}

	pvzID, err := parseUUID(r)
    if err != nil {
        http.Error(w, "Неверный запрос или приемка уже закрыта", http.StatusBadRequest)
        return
    }
	pvz := models.PVZ{
		ID: pvzID,
	}

	if err = s.db.CloseLastReception(r.Context(), pvz); err != nil {
		http.Error(w, "Неверный запрос или приемка уже закрыта", http.StatusBadRequest)
		return
	}
	writeResponse(w, http.StatusOK, "Приемка закрыта")
}

// GET /api/pvz 
func (s *MyService) GetPvz(w http.ResponseWriter, r *http.Request, params dto.GetPvzParams) {
	_, err := s.tokens.VerifyToken(r.Header.Get("Authorization"))
	if err != nil {
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}
	startDateStr := r.URL.Query().Get("startDate")
	endDateStr := r.URL.Query().Get("endDate")
	pageStr := r.URL.Query().Get("page")
	limitStr := r.URL.Query().Get("limit")


	startDate, endDate, err := ParseTime(startDateStr, endDateStr)
	if err != nil {
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}

	page := 1
	if pageStr != "" {
		page, err = strconv.Atoi(pageStr)
		if err != nil || page < 1 {
			http.Error(w, "Неверный запрос", http.StatusBadRequest)
			return
		}
	}

	limit := 10
	if limitStr != "" {
		limit, err = strconv.Atoi(limitStr)
		if err != nil || limit < 1 || limit > 30 {
			http.Error(w, "Неверный запрос", http.StatusBadRequest)
			return
		}
	}

	pvz, err := s.db.GetPVZInfo(r.Context(), startDate, endDate, page, limit)
	if err != nil {
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}
	writeResponse(w, http.StatusOK, pvz)
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

func ParseTime(start, end string) (time.Time, time.Time, error) {
	var startDate, endDate time.Time

	var err error

	if start != "" {
		startDate, err = time.Parse(time.RFC3339, start)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("error parsing start date: %w", err)
		}
	}
	if end != "" {
		endDate, err = time.Parse(time.RFC3339, end)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("error parsing end date: %w", err)
		}
	}

	return startDate, endDate, nil
}

func NewService(db db.Repository, logger *logrus.Logger) *MyService {
	return &MyService{
		db: db,
		tokens: JWTTokenManager{},
		logger:	logger,
	}
}