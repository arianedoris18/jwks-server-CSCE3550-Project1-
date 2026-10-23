package main

import (
	"crypto/rsa"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Key represents an RSA key stored in SQLite.
type Key struct {
	PrivateKey *rsa.PrivateKey
	Kid        string
	ExpiresAt  time.Time
}

// Server contains the SQLite database connection.
type Server struct {
	db *sql.DB
}

// JWK represents a public RSA key.
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

// NewServer initializes SQLite and ensures valid and expired keys exist.
func NewServer() (*Server, error) {
	db, err := initDB()
	if err != nil {
		return nil, err
	}

	var validCount int
	err = db.QueryRow(
		"SELECT COUNT(*) FROM keys WHERE exp >= ?",
		time.Now().Add(time.Hour).Unix(),
	).Scan(&validCount)
	if err != nil {
		db.Close()
		return nil, err
	}

	if validCount == 0 {
		if err := saveNewKey(db, time.Now().Add(2*time.Hour)); err != nil {
			db.Close()
			return nil, err
		}
	}

	var expiredCount int
	err = db.QueryRow(
		"SELECT COUNT(*) FROM keys WHERE exp <= ?",
		time.Now().Unix(),
	).Scan(&expiredCount)
	if err != nil {
		db.Close()
		return nil, err
	}

	if expiredCount == 0 {
		if err := saveNewKey(db, time.Now().Add(-time.Hour)); err != nil {
			db.Close()
			return nil, err
		}
	}

	return &Server{db: db}, nil
}

// base64URLEncode converts bytes to Base64URL encoding.
func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// publicKeyToJWK converts an RSA public key into JWK format.
func publicKeyToJWK(key Key) JWK {
	publicKey := &key.PrivateKey.PublicKey

	n := base64URLEncode(publicKey.N.Bytes())
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

// jwksHandler returns all unexpired public keys from SQLite.
func (s *Server) jwksHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	keys, err := getValidKeys(s.db)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	jwks := JWKS{Keys: []JWK{}}

	for _, key := range keys {
		jwks.Keys = append(jwks.Keys, publicKeyToJWK(key))
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		return
	}
}

// authHandler signs JWTs using RSA private keys stored in SQLite.
func (s *Server) authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	_, expired := r.URL.Query()["expired"]

	selectedKey, err := getKey(s.db, expired)
	if err != nil {
		http.Error(w, "Key not found", http.StatusInternalServerError)
		return
	}

	expiration := time.Now().Add(time.Hour)
	if expired {
		expiration = time.Now().Add(-time.Hour)
	}

	claims := jwt.MapClaims{
		"sub": "fake-user",
		"iat": time.Now().Unix(),
		"exp": expiration.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = selectedKey.Kid

	signedToken, err := token.SignedString(selectedKey.PrivateKey)
	if err != nil {
		http.Error(w, "Failed to sign token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/jwt")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(signedToken))
}

// routes registers the HTTP endpoints.
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/jwks.json", s.jwksHandler)
	mux.HandleFunc("/auth", s.authHandler)

	return mux
}
