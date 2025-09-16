package handlers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/ericychoi/otl/internal/jwt"
)

// Handler contains HTTP handlers for the OAuth2 endpoints
type Handler struct {
	expectedClientID     string
	expectedClientSecret string
	jwtService           *jwt.Service
	signaturePublicKey   string
	tokenBasicOnly       bool
}

// TokenResponse represents the response from the token endpoint
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// NewHandler creates a new handler
func NewHandler(cID, cSecret string, jwtService *jwt.Service, sp string, shouldTokenBasicOnly bool) *Handler {
	return &Handler{
		expectedClientID:     cID,
		expectedClientSecret: cSecret,
		jwtService:           jwtService,
		signaturePublicKey:   sp,
		tokenBasicOnly:       shouldTokenBasicOnly,
	}
}

// logRequest logs the full request details
func logRequest(r *http.Request) {
	// Dump the full request (headers, body, etc.)
	requestDump, err := httputil.DumpRequest(r, true)
	if err != nil {
		log.Printf("Error dumping request: %v", err)
		return
	}

	// Log the request with a timestamp
	log.Printf("Request received: %s %s\n%s", r.Method, r.URL.Path, string(requestDump))
}

// logRequest logs the full request details
func logResponse(message string, statusCode int) {
	log.Printf("Response: %s %d\n", message, statusCode)
}

// TokenRequest handles the OAuth2 token endpoint
func (h *Handler) TokenRequest(w http.ResponseWriter, r *http.Request) {
	logRequest(r)

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// try basic auth first
	var providedClientID, providedClientSecret string
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Basic ") {
		// Decode Basic auth
		payload, err := base64.StdEncoding.DecodeString(auth[6:])
		if err != nil {
			http.Error(w, "Invalid Authorization header", http.StatusBadRequest)
			return
		}

		// Split client_id:client_secret
		credentials := strings.SplitN(string(payload), ":", 2)
		if len(credentials) == 2 {
			providedClientID = credentials[0]
			providedClientSecret = credentials[1]
		}
	}

	// If credentials not in form data, check Authorization header (Basic auth)
	if !h.tokenBasicOnly && (providedClientID == "" || providedClientSecret == "") {
		// Parse form data
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Could not parse form data", http.StatusBadRequest)
			return
		}

		// Validate grant type
		grantType := r.Form.Get("grant_type")
		if grantType != "client_credentials" && grantType != "authorization_code" {
			http.Error(w, "Unsupported grant type", http.StatusBadRequest)
			return
		}

		// Validate client credentials - support both Basic auth and form data
		providedClientID = r.Form.Get("client_id")
		providedClientSecret = r.Form.Get("client_secret")
	}

	if providedClientID != h.expectedClientID || providedClientSecret != h.expectedClientSecret {
		http.Error(w, "Invalid client credentials", http.StatusUnauthorized)
		return
	}

	// Generate JWT token
	token, err := h.jwtService.GenerateToken()
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	// Create token response
	response := TokenResponse{
		AccessToken: token,
		TokenType:   "bearer",
		ExpiresIn:   60,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// AuthorizeRequest handles the OAuth2 authorization endpoint
func (h *Handler) AuthorizeRequest(w http.ResponseWriter, r *http.Request) {
	logRequest(r)

	// This is a dummy endpoint for the authorization endpoint
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("This is a minimal OAuth2 provider. The authorize endpoint is not fully implemented."))
}

// Discovery handles the OpenID Connect discovery endpoint
func (h *Handler) Discovery(w http.ResponseWriter, r *http.Request) {
	logRequest(r)

	baseURL := fmt.Sprintf("http://%s", r.Host)

	discovery := map[string]interface{}{
		"issuer":                 baseURL,
		"authorization_endpoint": baseURL + "/authorize",
		"token_endpoint":         baseURL + "/token",
		"jwks_uri":               baseURL + "/jwks",
		"response_types_supported": []string{
			"code",
			"token",
		},
		"grant_types_supported": []string{
			"authorization_code",
			"client_credentials",
		},
		"token_endpoint_auth_methods_supported": []string{
			"client_secret_basic",
			"client_secret_post",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(discovery)
}

// JWKS handles the JWK Set endpoint
func (h *Handler) JWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.jwtService.JWKS())
}
