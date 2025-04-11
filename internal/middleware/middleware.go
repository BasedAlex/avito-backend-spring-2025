package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/basedalex/avito-backend-2025-spring/internal/auth"
)

func Authentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/dummyLogin" {
			next.ServeHTTP(w, r)
			return
		}
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "Missing authorization header")
			return
		}
		parts := strings.Split(tokenString, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "Invalid authorization header format")
			return
		}
		_, err := auth.VerifyToken(parts[1])
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "Invalid token: ", err.Error())
			return
		}
		next.ServeHTTP(w, r)
	})
}