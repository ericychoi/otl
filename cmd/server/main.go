package main

import (
	"log"
	"net/http"

	"github.com/ericychoi/otl/internal/handlers"
	"github.com/ericychoi/otl/internal/jwt"
)

func main() {
	cfg, err := Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize JWT service with the private key
	jwtService, err := jwt.NewService(cfg.KeyPath)
	if err != nil {
		log.Fatalf("Failed to initialize JWT service: %v", err)
	}

	// Initialize handlers
	handler := handlers.NewHandler(cfg.ClientID, cfg.ClientSecret, jwtService)

	// Set up routes
	http.HandleFunc("/token", handler.TokenRequest)
	http.HandleFunc("/authorize", handler.AuthorizeRequest)
	http.HandleFunc("/.well-known/openid-configuration", handler.Discovery)
	http.HandleFunc("/jwks", handler.JWKS)
	http.HandleFunc("/webhook", handler.Webhook)

	// Start server
	log.Printf("Starting OAuth2 server on port %s", cfg.Port)
	log.Fatal(http.ListenAndServe(":"+cfg.Port, nil))
}
