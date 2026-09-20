package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Key represents an RSA key pair used by the JWKS server.
type Key struct {
	PrivateKey *rsa.PrivateKey
	Kid        string
	ExpiresAt  time.Time
}

// Server contains the valid and expired signing keys.
type Server struct {
	validKey   Key
	expiredKey Key
}

// JWK represents a public RSA key in JSON Web Key format.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// NewServer creates one valid RSA key and one expired RSA key.
func NewServer() (*Server, error) {
	validPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	expiredPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	return &Server{
		validKey: Key{
			PrivateKey: validPrivateKey,
			Kid:        "valid-key",
			ExpiresAt:  time.Now().Add(1 * time.Hour),
		},

		expiredKey: Key{
			PrivateKey: expiredPrivateKey,
			Kid:        "expired-key",
			ExpiresAt:  time.Now().Add(-1 * time.Hour),
		},
	}, nil
}

// base64URLEncode converts bytes to Base64URL encoding without padding.
func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// publicKeyToJWK converts an RSA public key into JWK format.
func publicKeyToJWK(key Key) JWK {
	publicKey := &key.PrivateKey.PublicKey

	// Convert RSA modulus to Base64URL.
	n := base64URLEncode(publicKey.N.Bytes())

	// Convert RSA exponent to Base64URL.
	eBytes := big.NewInt(int64(publicKey.E)).Bytes()
	e := base64URLEncode(eBytes)

	return JWK{
		Kty: "RSA",
		Use: "sig",
		Kid: key.Kid,
		Alg: "RS256",
		N:   n,
		E:   e,
	}
}

// jwksHandler serves the public keys in JWKS format.
func (s *Server) jwksHandler(
	w http.ResponseWriter,
	r *http.Request,
) {
	// Only GET requests are allowed.
	if r.Method != http.MethodGet {
		http.Error(
			w,
			"Method not allowed",
			http.StatusMethodNotAllowed,
		)
		return
	}

	keys := []JWK{}

	// Only include keys that have NOT expired.
	if time.Now().Before(s.validKey.ExpiresAt) {
		keys = append(
			keys,
			publicKeyToJWK(s.validKey),
		)
	}

	// Normally this will NOT be added because
	// the expired key's expiration time is in the past.
	if time.Now().Before(s.expiredKey.ExpiresAt) {
		keys = append(
			keys,
			publicKeyToJWK(s.expiredKey),
		)
	}

	response := JWKS{
		Keys: keys,
	}

	w.Header().Set(
		"Content-Type",
		"application/json",
	)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(
			w,
			"Failed to encode JWKS",
			http.StatusInternalServerError,
		)
	}
}

// authHandler creates and returns a signed JWT.
func (s *Server) authHandler(
	w http.ResponseWriter,
	r *http.Request,
) {
	// The assignment requires POST /auth.
	if r.Method != http.MethodPost {
		http.Error(
			w,
			"Method not allowed",
			http.StatusMethodNotAllowed,
		)
		return
	}

	// Normally use the valid key.
	selectedKey := s.validKey

	// Normal JWT expires one hour from now.
	expiration := time.Now().Add(1 * time.Hour)

	// If the "expired" query parameter is present,
	// use the expired key and an expiration time in the past.
	if _, exists := r.URL.Query()["expired"]; exists {
		selectedKey = s.expiredKey
		expiration = time.Now().Add(-1 * time.Hour)
	}

	// Create JWT claims.
	claims := jwt.MapClaims{
		"sub": "fake-user",
		"iat": time.Now().Unix(),
		"exp": expiration.Unix(),
	}

	// Create the JWT using RS256.
	token := jwt.NewWithClaims(
		jwt.SigningMethodRS256,
		claims,
	)

	// ==================================================
	// IMPORTANT LINE #1:
	// Add the key ID to the JWT header.
	// ==================================================
	token.Header["kid"] = selectedKey.Kid

	// Sign the JWT using the selected RSA private key.
	signedToken, err := token.SignedString(
		selectedKey.PrivateKey,
	)

	if err != nil {
		http.Error(
			w,
			"Failed to sign token",
			http.StatusInternalServerError,
		)
		return
	}

	// Return the JWT.
	w.Header().Set(
		"Content-Type",
		"application/jwt",
	)

	w.WriteHeader(http.StatusOK)

	_, _ = w.Write(
		[]byte(signedToken),
	)
}

// routes registers the HTTP endpoints.
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	// ==================================================
	// IMPORTANT LINE #2:
	// Register the well-known JWKS endpoint.
	// ==================================================
	mux.HandleFunc(
		"/.well-known/jwks.json",
		s.jwksHandler,
	)

	// Register the authentication endpoint.
	mux.HandleFunc(
		"/auth",
		s.authHandler,
	)

	return mux
}
