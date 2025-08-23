package handlers

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
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

	// Token is valid, check if there is a signature
	s := r.Header.Get("X-Twilio-Email-Event-Webhook-Signature")
	if s == "" {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"success","message":"OAuth Token is valid"}`))
		return
	}
	ts := r.Header.Get("X-Twilio-Email-Event-Webhook-Timestamp")
	if ts == "" {
		http.Error(w, fmt.Sprintf("signature detected but timestamp missing: %v", err), http.StatusUnauthorized)
		return
	}

	// verify signature foillowing Twilio's guidelines
	// https://www.twilio.com/docs/sendgrid/for-developers/tracking-events/getting-started-event-webhook-security-features#verify-the-signature
	signatureBytes, _ := base64.StdEncoding.DecodeString(s)
	ecdsaSig := struct {
		R *big.Int
		S *big.Int
	}{}
	asn1.Unmarshal(signatureBytes, &ecdsaSig)
	tsBytes := []byte(ts)
	payload, _ := io.ReadAll(r.Body)
	sha := sha256.New()
	sha.Write(tsBytes)
	sha.Write(payload)
	hashedPayload := sha.Sum(nil)

	// Parse the public key from string to *ecdsa.PublicKey
	publicKeyBytes, err := base64.StdEncoding.DecodeString(h.signaturePublicKey)
	if err != nil {
		http.Error(w, "Invalid public key format", http.StatusInternalServerError)
		return
	}

	// Parse DER-encoded public key directly
	publicKeyInterface, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		http.Error(w, "Failed to parse public key", http.StatusInternalServerError)
		return
	}

	publicKey, ok := publicKeyInterface.(*ecdsa.PublicKey)
	if !ok {
		http.Error(w, "Public key is not ECDSA", http.StatusInternalServerError)
		return
	}

	if !ecdsa.Verify(publicKey, hashedPayload, ecdsaSig.R, ecdsaSig.S) {
		http.Error(w, "Signature verification failed", http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"success","message":"Token is valid"}`))
}
