package jwt

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// Service handles JWT operations
type Service struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// NewService creates a new JWT service
func NewService(privateKeyPath string) (*Service, error) {
	// Load private key for JWT signing
	keyData, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return &Service{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
	}, nil
}

// GenerateToken creates a new JWT token
func (s *Service) GenerateToken() (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": "test-oauth2-provider",
		"sub": "test-subject",
		"aud": "test-audience",
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
		"jti": fmt.Sprintf("%d", now.UnixNano()),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(s.privateKey)
}

// JWKS returns the JWKS representation of the public key
func (s *Service) JWKS() JWKS {
	return JWKS{
		Keys: []JWK{
			{
				Kty: "RSA",
				Kid: "key1",
				Use: "sig",
				Alg: "RS256",
				N:   base64URLEncode(s.publicKey.N.Bytes()),
				E:   base64URLEncode(big.NewInt(int64(s.publicKey.E)).Bytes()),
			},
		},
	}
}

// PublicKey returns the RSA public key used for token verification
func (s *Service) PublicKey() *rsa.PublicKey {
	return s.publicKey
}

func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
