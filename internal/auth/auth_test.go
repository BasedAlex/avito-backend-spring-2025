package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/require"
)

var testSecretKey = []byte("test-secret")

func init() {
	setSecretKey(testSecretKey)
}

func TestCreateToken(t *testing.T) {
	tests := []struct {
		name  string
		role  string
		email string
	}{
		{
			name:  "valid token",
			role:  "employee",
			email: "user@example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenString, err := CreateToken(tt.role, tt.email)
			require.NoError(t, err)
			require.NotEmpty(t, tokenString)

			parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					t.Fatalf("unexpected signing method: %v", token.Header["alg"])
				}
				return testSecretKey, nil
			})
			require.NoError(t, err)
			require.True(t, parsedToken.Valid)

			claims, ok := parsedToken.Claims.(jwt.MapClaims)
			require.True(t, ok)

			require.Equal(t, tt.role, claims["role"])
			require.Equal(t, tt.email, claims["email"])

			exp, ok := claims["exp"].(float64)
			require.True(t, ok)
			require.True(t, int64(exp) > time.Now().Unix())
		})
	}
}


func TestVerifyToken(t *testing.T) {
	t.Run("valid token", func(t *testing.T) {
		token, err := CreateToken("moderator", "test@example.com")
		require.NoError(t, err)

		authData, err := VerifyToken(token)
		require.NoError(t, err)
		require.Equal(t, "moderator", authData.Role)
		require.Equal(t, "test@example.com", authData.Email)
	})

	t.Run("invalid signing method", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS384, jwt.MapClaims{
			"role":  "employee",
			"email": "test@example.com",
			"exp":   time.Now().Add(time.Hour * 24).Unix(),
		})
		
		malformedToken, err := token.SignedString([]byte("wrongsecret"))
		require.NoError(t, err)
	
		_, err = VerifyToken(malformedToken)
		require.Error(t, err)
		
		require.ErrorContains(t, err, "parse error: signature is invalid")
	})

	t.Run("expired token", func(t *testing.T) {
		expiredToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"role":  "moderator",
			"email": "test@example.com",
			"exp":   time.Now().Add(-time.Hour).Unix(), 
		})
		tokenString, err := expiredToken.SignedString(secretKey)
		require.NoError(t, err)

		_, err = VerifyToken(tokenString)
		require.ErrorContains(t, err, "Token is expired") 
	})

	t.Run("invalid claims", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"role":  "moderator",
			"email": "test@example.com",
		})
		tokenString, err := token.SignedString(secretKey)
		require.NoError(t, err)

		_, err = VerifyToken(tokenString)
		require.ErrorContains(t, err, "token expired")
	})

	t.Run("malformed token", func(t *testing.T) {
		_, err := VerifyToken("invalid.token.string")
		require.Error(t, err)
		require.Contains(t, err.Error(), "parse error")
	})
}
