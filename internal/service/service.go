package service

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/basedalex/avito-backend-2025-spring/internal/auth"
	"github.com/basedalex/avito-backend-2025-spring/internal/db"
	"github.com/basedalex/avito-backend-2025-spring/internal/db/models"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

//go:generate mockgen -source=service.go -destination=../mocks/mock_service.go -package=mocks
type Service interface {
	DummyLoginHandler(w http.ResponseWriter, r *http.Request)
	RegisterUserHandler(w http.ResponseWriter, r *http.Request)
	LoginUserHandler(w http.ResponseWriter, r *http.Request)
	CreatePVZHandler(w http.ResponseWriter, r *http.Request)
	PostReceptionHandler(w http.ResponseWriter, r *http.Request)
	AddProductsHandler(w http.ResponseWriter, r *http.Request) 
	DeleteLastProductHandler(w http.ResponseWriter, r *http.Request)
	CloseLastReceptionHandler(w http.ResponseWriter, r *http.Request)
	GetPVZHandler(w http.ResponseWriter, r *http.Request)
}


type MyService struct {
	db db.Repository
	// cfg *config.Config
	// logger logrus.Logger
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
	var reqUser models.User

	if err := json.NewDecoder(r.Body).Decode(&reqUser); err != nil {
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}

	if reqUser.Email == "" || reqUser.Password == "" || reqUser.Role == "" {
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(reqUser.Password), bcrypt.DefaultCost)
	if err != nil {
		return
	}

	reqUser.ID = uuid.New()
	reqUser.Password = string(hashedPassword)

	if err := s.db.RegisterUser(r.Context(), reqUser); err != nil {
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}

	token, err := s.tokens.CreateToken(reqUser.Role, reqUser.Email)
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
	var pvz models.PVZ

	if err := json.NewDecoder(r.Body).Decode(&pvz); err != nil {
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}
	pvz.ID = uuid.New()
	pvz.RegistrationDate = time.Now().UTC()
	if err = s.db.CreatePVZ(r.Context(), pvz); err != nil {
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}
	writeResponse(w, http.StatusCreated, nil)
}

// POST /api/receptions
func (s *MyService) PostReceptionHandler(w http.ResponseWriter, r *http.Request) {
	data, err := s.tokens.VerifyToken(r.Header.Get("Authorization"))
	if err != nil {
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}
	if data.Role != "client" { 
		http.Error(w, "Доступ запрещён", http.StatusForbidden)
		return
	}

	var req struct {
		PVZID string `json:"pvz_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Неверный запрос или есть незакрытая приемка", http.StatusBadRequest)
		return
	}

	PVZUUID, err  := uuid.Parse(req.PVZID)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Неверный запрос или есть незакрытая приемка", http.StatusBadRequest)
		return
	}


	status, err := s.db.CheckReceptionStatus(r.Context(), PVZUUID); 
	if err != nil || status == "in_progress" {
		http.Error(w, "Неверный запрос или есть незакрытая приемка", http.StatusBadRequest)
	}

	createReceptionRequest := &models.Reception{
		ID: uuid.New(),
		PVZID: PVZUUID,
		ReceivedAt: time.Now().UTC(),
		Status: status,
	}

	if err = s.db.CreateReception(r.Context(), createReceptionRequest); err != nil {
		http.Error(w, "Неверный запрос или есть незакрытая приемка", http.StatusBadRequest)
		return
	}
	writeResponse(w, http.StatusCreated, nil)
}

// POST /api/products
func (s *MyService) AddProductsHandler(w http.ResponseWriter, r *http.Request) {
	data, err := s.tokens.VerifyToken(r.Header.Get("Authorization"))
	if err != nil {
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}
	if data.Role != "client" { 
		http.Error(w, "Доступ запрещён", http.StatusForbidden)
		return
	}

	var req struct {
		PVZID 			string 	`json:"pvzId"`
		Product_type 	string 	`json:"type"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Неверный запрос или нет активной приемки", http.StatusBadRequest)
		return
	}

	if req.Product_type != "электроника" && req.Product_type != "одежда" && req.Product_type != "обувь" {
		http.Error(w, "Неверный запрос или нет активной приемки", http.StatusBadRequest)
		return
	}

	PVZUUID, err  := uuid.Parse(req.PVZID)
	if err != nil {
		http.Error(w, "Неверный запрос или нет активной приемки", http.StatusBadRequest)
		return
	}

	status, err := s.db.CheckReceptionStatus(r.Context(), PVZUUID); 
	if err != nil || status != "in_progress" {
		http.Error(w, "Неверный запрос или нет активной приемки", http.StatusBadRequest)
	}


	product := &models.Product{
		ID: uuid.New(),
		ReceivedAt: time.Now().UTC(),
		Type: req.Product_type,
		ReceptionID: PVZUUID,
	}

	if err = s.db.AddProducts(r.Context(), product); err != nil {
		http.Error(w, "Неверный запрос или нет активной приемки", http.StatusBadRequest)
		return
	}
	writeResponse(w, http.StatusCreated, nil)

}


// POST /api/pvz/{pvzId}/delete_last_product
func (s *MyService) DeleteLastProductHandler(w http.ResponseWriter, r *http.Request) {
	data, err := s.tokens.VerifyToken(r.Header.Get("Authorization"))
	if err != nil {
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}
	if data.Role != "client" { 
		http.Error(w, "Доступ запрещён", http.StatusForbidden)
		return
	}

	pvzID := chi.URLParam(r, "pvzId")
    if pvzID == "" {
        http.Error(w, "Неверный запрос, нет активной приемки или нет товаров для удаления", http.StatusBadRequest)
        return
    }

	if err = s.db.DeleteLastProduct(pvzID); err != nil {
		http.Error(w, "Неверный запрос, нет активной приемки или нет товаров для удаления", http.StatusBadRequest)
		return
	}
	
	writeResponse(w, http.StatusOK, nil)
}

// POST /api/pvz/{pvzId}/close_last_reception
func (s *MyService) CloseLastReceptionHandler(w http.ResponseWriter, r *http.Request) {
	data, err := s.tokens.VerifyToken(r.Header.Get("Authorization"))
	if err != nil {
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}
	if data.Role != "client" { 
		http.Error(w, "Доступ запрещён", http.StatusForbidden)
		return
	}

	pvzID := chi.URLParam(r, "pvzId")
    if pvzID == "" {
        http.Error(w, "Неверный запрос или приемка уже закрыта", http.StatusBadRequest)
        return
    }

	if err = s.db.CloseLastReception(pvzID); err != nil {
		http.Error(w, "Неверный запрос или приемка уже закрыта", http.StatusBadRequest)
		return
	}
	writeResponse(w, http.StatusOK, "Приемка закрыта")
}

// GET /api/pvz 
func (s *MyService) GetPVZHandler(w http.ResponseWriter, r *http.Request) {
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

	pvz, err := s.db.GetPVZInfo(startDate, endDate, page, limit)
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

func NewService(db db.Repository) *MyService {
	return &MyService{
		db: db,
		tokens: JWTTokenManager{},
	}
}