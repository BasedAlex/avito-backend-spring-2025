package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"
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
	logger *logrus.Logger
	tokens TokenManager
}

func NewService(db db.Repository, logger *logrus.Logger) *MyService {
	return &MyService{
		db: db,
		tokens: JWTTokenManager{},
		logger:	logger,
	}
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

// (POST /dummyLogin)
func (s *MyService) PostDummyLogin(w http.ResponseWriter, r *http.Request) {
	var req dto.PostDummyLoginJSONBody

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || (req.Role != "employee" && req.Role != "moderator") {
		s.logger.Errorf("Failed to decode request body %v", err)
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}

	var email string
	
	if req.Role == "employee" {
		email = "employee@mail.ru"
	} else {
		email = "moderator@mail.ru"
	}

	token, err := s.tokens.CreateToken(string(req.Role), email)
	if err != nil {
		s.logger.Errorf("Failed to create token %v", err)
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}

	writeResponse(w, http.StatusOK, map[string]string{"token": token})
}

// (POST /register)
func (s *MyService) PostRegister(w http.ResponseWriter, r *http.Request) {
	var req dto.PostRegisterJSONRequestBody

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Errorf("Failed to decode request body %v", err)
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.Password == "" || req.Role == "" {
		s.logger.Errorf("Invalid request body %v", req)
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		s.logger.Errorf("Couldn't generate hashed password %v", err)
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}

	reqUser := models.User{
		ID: uuid.New(),
		Email: string(req.Email),
		Password: string(hashedPassword),
		Role: string(req.Role),
	}

	user, err := s.db.RegisterUser(r.Context(), reqUser); 
	if err != nil {
		s.logger.Error("Error registering new user ", err)
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}

	type AuthResponse struct {
		Token string      `json:"token"`
		User  models.User `json:"user"`
	}

	token, err := s.tokens.CreateToken(reqUser.Role, reqUser.Email)
	if err != nil {
		s.logger.Errorf("Couldn't create token %v", err)
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}

	writeResponse(w, http.StatusCreated, AuthResponse{Token: token, User: user})
}

// (POST /login)
func (s *MyService) PostLogin(w http.ResponseWriter, r *http.Request) {
	var req dto.PostLoginJSONRequestBody

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" || req.Password == "" {
		s.logger.Errorf("Failed parsing json %v", req)
		http.Error(w, "Неверные учетные данные", http.StatusUnauthorized)
		return
	}
	
	user, err := s.db.GetUserByEmail(string(req.Email))
	if err != nil {
		http.Error(w, "Неверные учетные данные", http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password))
	if err != nil {
		http.Error(w, "Неверные учетные данные", http.StatusUnauthorized)
		return
	}

	token, err := s.tokens.CreateToken(user.Role, string(req.Email))
	if err != nil {
		http.Error(w, "Неверные учетные данные", http.StatusUnauthorized)
		return
	}

	writeResponse(w, http.StatusOK, map[string]string{"token": token})
}

// POST /pvz
func (s *MyService) PostPvz(w http.ResponseWriter, r *http.Request) {
	data, err := s.tokens.VerifyToken(r.Header.Get("Authorization"))
	if err != nil {
		s.logger.Errorf("Failed to verify token %v", err)
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}
	ok := checkRole(data.Role, r.Method, "/pvz")
	if !ok { 
		s.logger.Error("role is not correct ", data.Role)
		http.Error(w, "Доступ запрещён", http.StatusForbidden)
		return
	}
	var req dto.PostPvzJSONRequestBody

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Errorf("Failed to decode request body %v", err)
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}
	pvz := models.PVZ{
		ID:       			uuid.New(),
		RegistrationDate: 	time.Now().UTC(),
		City: 				string(req.City),
	}

	newPVZ, err := s.db.CreatePVZ(r.Context(), pvz); 
	if err != nil {
		s.logger.Errorf("Failed to create pvz %v", err)
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}
	writeResponse(w, http.StatusCreated, newPVZ)
}

// POST /receptions
func (s *MyService) PostReceptions(w http.ResponseWriter, r *http.Request) {
	data, err := s.tokens.VerifyToken(r.Header.Get("Authorization"))
	if err != nil {
		s.logger.Errorf("Failed to verify token %v", err)
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}
	
	ok := checkRole(data.Role, r.Method, "/receptions")
	if !ok { 
		s.logger.Error("role is not correct", data.Role)
		http.Error(w, "Доступ запрещён", http.StatusForbidden)
		return
	}

	var req dto.PostReceptionsJSONRequestBody

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Errorf("Failed to decode request body %v", err)
		http.Error(w, "Неверный запрос или есть незакрытая приемка", http.StatusBadRequest)
		return
	}

	createReceptionRequest := models.CreateReceptionRequest(req.PvzId)

	reception, err := s.db.CreateReception(r.Context(), createReceptionRequest); 
	if err != nil {
		s.logger.Warn("Failed to create reception", err)
		http.Error(w, "Неверный запрос или есть незакрытая приемка", http.StatusBadRequest)
		return
	}
	s.logger.Info("Reception created", reception)
	writeResponse(w, http.StatusCreated, reception)
}

// POST /products
func (s *MyService) PostProducts(w http.ResponseWriter, r *http.Request) {
	data, err := s.tokens.VerifyToken(r.Header.Get("Authorization"))
	if err != nil {
		s.logger.Error("Failed to verify token", err)
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}
	ok := checkRole(data.Role, r.Method, "/products")
	if !ok { 
		s.logger.Error("role is not correct", data.Role)
		http.Error(w, "Доступ запрещён", http.StatusForbidden)
		return
	}

	var req dto.PostProductsJSONBody

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Error("Failed to decode request body", err)
		http.Error(w, "Неверный запрос или нет активной приемки", http.StatusBadRequest)
		return
	}

	s.logger.Infof("request: %+v", req)

	productType, ok := models.ProductTypes[strings.ToLower(string(req.Type))]
	if !ok {
		s.logger.Error("Invalid product type", req.Type)
		http.Error(w, "Неверный запрос или нет активной приемки", http.StatusBadRequest)
		return
	}

	product := models.CreateProduct(productType)

	newProduct, err := s.db.AddProducts(r.Context(), product, req.PvzId)
	if err != nil {
		s.logger.Error("Error adding product", err)
		http.Error(w, "Неверный запрос или нет активной приемки", http.StatusBadRequest)
		return
	}

	s.logger.Info("product added ", newProduct)

	writeResponse(w, http.StatusCreated, newProduct)
}

// POST /pvz/{pvzId}/delete_last_product
func (s *MyService) PostPvzPvzIdDeleteLastProduct(w http.ResponseWriter, r *http.Request, pvzId uuid.UUID) {
	data, err := s.tokens.VerifyToken(r.Header.Get("Authorization"))
	if err != nil {
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}

	ok := checkRole(data.Role, r.Method, "/pvz/{pvzId}/delete_last_product")
	if !ok { 
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

// POST /pvz/{pvzId}/close_last_reception
func (s *MyService) PostPvzPvzIdCloseLastReception(w http.ResponseWriter, r *http.Request, pvzId uuid.UUID) {
	data, err := s.tokens.VerifyToken(r.Header.Get("Authorization"))
	if err != nil {
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}
	ok := checkRole(data.Role, r.Method, "/pvz/{pvzId}/delete_last_product")
	if !ok { 
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
	
	lastReception, err := s.db.CloseLastReception(r.Context(), pvz); 
	if err != nil {
		http.Error(w, "Неверный запрос или приемка уже закрыта", http.StatusBadRequest)
		return
	}

	writeResponse(w, http.StatusOK, lastReception)
}

// GET /pvz 
func (s *MyService) GetPvz(w http.ResponseWriter, r *http.Request, params dto.GetPvzParams) {
	data, err := s.tokens.VerifyToken(r.Header.Get("Authorization"))
	if err != nil {
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}

	ok := checkRole(data.Role, r.Method, "/pvz")
	if !ok { 
		http.Error(w, "Доступ запрещён", http.StatusForbidden)
		return
	}

	startDateStr := r.URL.Query().Get("startDate")
	endDateStr := r.URL.Query().Get("endDate")
	pageStr := r.URL.Query().Get("page")
	limitStr := r.URL.Query().Get("limit")


	startDate, endDate, err := parseTime(startDateStr, endDateStr)
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

func parseTime(start, end string) (time.Time, time.Time, error) {
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

func checkRole(role, method, path string) bool {
	var routes = map[string][]string{
		"POST /products":                           {"employee"},
		"POST /pvz/{pvzId}/close_last_reception":   {"employee"},
		"POST /pvz/{pvzId}/delete_last_product":    {"employee"},
		"POST /receptions":                         {"employee"},
		"POST /pvz": 								{"moderator"},
		"GET /pvz": 								{"moderator", "employee"},
	}

	key := method + " " + path

	roles, ok := routes[key]
	if !ok {
		return false
	}
	
	for _, r := range roles {
		if r == role {
			return true
		}
	}

	fmt.Println("ROLE", role)
	fmt.Println("METHOD", method)
	fmt.Println("PATH", path)
	testRoles := routes[path]
	fmt.Println("CONTAINS?", slices.Contains(testRoles, role))

	return false 
}