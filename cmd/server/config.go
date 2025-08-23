package main

import (
	"github.com/kelseyhightower/envconfig"
)

// Config holds all configuration from environment variables
type Config struct {
	ClientID           string `envconfig:"OAUTH_CLIENT_ID" default:"test-client-id"`
	ClientSecret       string `envconfig:"OAUTH_CLIENT_SECRET" default:"test-client-secret"`
	Port               string `envconfig:"PORT" default:"8080"`
	KeyPath            string `envconfig:"KEY_PATH" default:"keys/private.pem"`
	PublicKeyPath      string `envconfig:"PUBLIC_KEY_PATH" default:"keys/public.pem"`
	SignaturePublicKey string `envconfig:"TWILIO_SIGNATURE_PUBLIC_KEY" default:""`
	// SSL/TLS Configuration
	TLSCertPath string `envconfig:"TLS_CERT_PATH" default:"keys/server.crt"`
	TLSKeyPath  string `envconfig:"TLS_KEY_PATH" default:"keys/server.key"`
	EnableHTTPS bool   `envconfig:"ENABLE_HTTPS" default:"false"`
}

// Load loads configuration from environment variables
func Load() (*Config, error) {
	var cfg Config
	if err := envconfig.Process("", &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
