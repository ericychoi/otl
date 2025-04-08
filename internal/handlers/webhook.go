package handlers

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

func (h *Handler) Webhook(w http.ResponseWriter, r *http.Request) {
	logRequest(r)

	// Extract token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Authorization header required", http.StatusUnauthorized)
		return
	}

	// Check for Bearer token format
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		http.Error(w, "Authorization header format must be 'Bearer {token}'", http.StatusUnauthorized)
		return
	}

	tokenString := parts[1]

	// Parse and verify the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify that the signing method is what we expect
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Return the public key for verification
		return h.jwtService.PublicKey(), nil
	})

	// Handle parsing/verification errors
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid token: %v", err), http.StatusUnauthorized)
		return
	}

	// Check if token is valid
	if !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Token is valid, return success response
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"success","message":"Token is valid"}`))
}
