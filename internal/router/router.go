package router

import (
	"net/http"

	"github.com/basedalex/avito-backend-2025-spring/internal/middleware"
	"github.com/basedalex/avito-backend-2025-spring/internal/service"
	"github.com/go-chi/chi/v5"
)

func NewRouter(svc service.Service) http.Handler {
	r := chi.NewRouter()

	// Public routes
	r.Post("/api/dummyLogin", svc.DummyLoginHandler)
	r.Post("/api/register", svc.RegisterUserHandler)
	r.Post("/api/auth", svc.LoginUserHandler)

	// mw

	r.Route("/api", func(r chi.Router) {
		r.Use(middleware.Authentication)
		r.Get("/pvz", svc.GetPVZHandler)
		r.Post("/pvz", svc.CreatePVZHandler)
		r.Post("/receptions", svc.PostReceptionHandler)
		r.Post("/products", svc.AddProductsHandler)
		r.Post("/pvz/{pvzId}/delete_last_product", svc.DeleteLastProductHandler)
		r.Post("/pvz/{pvzId}/close_last_reception", svc.CloseLastReceptionHandler)
	})

	return r
}