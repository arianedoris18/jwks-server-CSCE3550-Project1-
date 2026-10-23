package main

import (
	"crypto/rsa"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "modernc.org/sqlite"
)

// createTestServer uses a separate SQLite database for each test.
func createTestServer(t *testing.T) *Server {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "test_keys.db")

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		db.Close()
	})

	_, err = db.Exec(`CREATE TABLE keys (
		kid INTEGER PRIMARY KEY AUTOINCREMENT,
		key BLOB NOT NULL,
		exp INTEGER NOT NULL
	)`)
	if err != nil {
		t.Fatal(err)
	}

	if err := saveNewKey(db, time.Now().Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}

	if err := saveNewKey(db, time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}

	return &Server{db: db}
}

func TestJWKSReturnsValidKey(t *testing.T) {
	server := createTestServer(t)

	request := httptest.NewRequest(
		http.MethodGet,
		"/.well-known/jwks.json",
		nil,
	)
	recorder := httptest.NewRecorder()

	server.jwksHandler(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", recorder.Code)
	}

	var jwks JWKS
	if err := json.Unmarshal(recorder.Body.Bytes(), &jwks); err != nil {
		t.Fatal(err)
	}

	if len(jwks.Keys) != 1 {
		t.Fatalf("Expected 1 valid key, got %d", len(jwks.Keys))
	}

	validKey, err := getKey(server.db, false)
	if err != nil {
		t.Fatal(err)
	}

	jwk := jwks.Keys[0]

	if jwk.Kid != validKey.Kid {
		t.Errorf("Expected kid %s, got %s", validKey.Kid, jwk.Kid)
	}

	if jwk.Kty != "RSA" || jwk.Alg != "RS256" {
		t.Error("Invalid JWK key type or algorithm")
	}

	if jwk.N == "" || jwk.E == "" {
		t.Error("JWK missing RSA public key components")
	}
}

func TestJWKSDoesNotReturnExpiredKey(t *testing.T) {
	server := createTestServer(t)

	request := httptest.NewRequest(
		http.MethodGet,
		"/.well-known/jwks.json",
		nil,
	)
	recorder := httptest.NewRecorder()

	server.jwksHandler(recorder, request)

	var jwks JWKS
	if err := json.Unmarshal(recorder.Body.Bytes(), &jwks); err != nil {
		t.Fatal(err)
	}

	expiredKey, err := getKey(server.db, true)
	if err != nil {
		t.Fatal(err)
	}

	for _, key := range jwks.Keys {
		if key.Kid == expiredKey.Kid {
			t.Error("JWKS must not contain expired keys")
		}
	}
}

func TestJWKSRejectsPost(t *testing.T) {
	server := createTestServer(t)

	request := httptest.NewRequest(
		http.MethodPost,
		"/.well-known/jwks.json",
		nil,
	)
	recorder := httptest.NewRecorder()

	server.jwksHandler(recorder, request)

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", recorder.Code)
	}
}

func TestAuthReturnsJWT(t *testing.T) {
	server := createTestServer(t)

	request := httptest.NewRequest(http.MethodPost, "/auth", nil)
	recorder := httptest.NewRecorder()

	server.authHandler(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s",
			recorder.Code, recorder.Body.String())
	}

	validKey, err := getKey(server.db, false)
	if err != nil {
		t.Fatal(err)
	}

	token, err := jwt.Parse(
		recorder.Body.String(),
		func(token *jwt.Token) (interface{}, error) {
			if token.Method != jwt.SigningMethodRS256 {
				return nil, errors.New("unexpected signing method")
			}
			return &validKey.PrivateKey.PublicKey, nil
		},
	)

	if err != nil {
		t.Fatalf("Failed to verify JWT: %v", err)
	}

	if !token.Valid {
		t.Error("Expected valid JWT")
	}

	if token.Header["kid"] != validKey.Kid {
		t.Errorf("Incorrect JWT kid: %v", token.Header["kid"])
	}
}

func TestExpiredAuthReturnsExpiredJWT(t *testing.T) {
	server := createTestServer(t)

	request := httptest.NewRequest(
		http.MethodPost,
		"/auth?expired=true",
		nil,
	)
	recorder := httptest.NewRecorder()

	server.authHandler(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", recorder.Code)
	}

	expiredKey, err := getKey(server.db, true)
	if err != nil {
		t.Fatal(err)
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())

	token, err := parser.Parse(
		recorder.Body.String(),
		func(token *jwt.Token) (interface{}, error) {
			return &expiredKey.PrivateKey.PublicKey, nil
		},
	)

	if err != nil {
		t.Fatalf("Failed to verify expired JWT signature: %v", err)
	}

	if token.Header["kid"] != expiredKey.Kid {
		t.Errorf("Incorrect expired JWT kid: %v", token.Header["kid"])
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("Could not read JWT claims")
	}

	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		t.Fatal("Missing JWT expiration")
	}

	if !exp.Before(time.Now()) {
		t.Error("Expected JWT to be expired")
	}
}

func TestAuthRejectsGet(t *testing.T) {
	server := createTestServer(t)

	request := httptest.NewRequest(http.MethodGet, "/auth", nil)
	recorder := httptest.NewRecorder()

	server.authHandler(recorder, request)

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", recorder.Code)
	}
}

func TestRoutes(t *testing.T) {
	server := createTestServer(t)

	testServer := httptest.NewServer(server.routes())
	defer testServer.Close()

	response, err := http.Get(
		testServer.URL + "/.well-known/jwks.json",
	)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}

	if response.StatusCode != http.StatusOK {
		t.Errorf("Expected 200, got %d: %s",
			response.StatusCode, string(body))
	}
}

func TestDatabaseStoresKeys(t *testing.T) {
	server := createTestServer(t)

	var count int
	err := server.db.QueryRow(
		"SELECT COUNT(*) FROM keys",
	).Scan(&count)

	if err != nil {
		t.Fatal(err)
	}

	if count != 2 {
		t.Errorf("Expected 2 stored keys, got %d", count)
	}
}

func TestGetValidAndExpiredKeys(t *testing.T) {
	server := createTestServer(t)

	validKey, err := getKey(server.db, false)
	if err != nil {
		t.Fatal(err)
	}

	expiredKey, err := getKey(server.db, true)
	if err != nil {
		t.Fatal(err)
	}

	if !validKey.ExpiresAt.After(time.Now()) {
		t.Error("Valid key should not be expired")
	}

	if expiredKey.ExpiresAt.After(time.Now()) {
		t.Error("Expired key should not be valid")
	}

	if validKey.Kid == expiredKey.Kid {
		t.Error("Key IDs must be unique")
	}
}

func TestGetValidKeys(t *testing.T) {
	server := createTestServer(t)

	keys, err := getValidKeys(server.db)
	if err != nil {
		t.Fatal(err)
	}

	if len(keys) != 1 {
		t.Fatalf("Expected 1 valid key, got %d", len(keys))
	}
}

func TestKeyPersistence(t *testing.T) {
	server := createTestServer(t)

	validKey, err := getKey(server.db, false)
	if err != nil {
		t.Fatal(err)
	}

	var dbPath string
	err = server.db.QueryRow("PRAGMA database_list").Scan(
		new(int), new(string), &dbPath,
	)
	if err != nil {
		t.Fatal(err)
	}

	reopened, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()

	reloadedKey, err := getKey(reopened, false)
	if err != nil {
		t.Fatal(err)
	}

	if validKey.Kid != reloadedKey.Kid {
		t.Error("Key ID changed after reopening database")
	}

	if validKey.PrivateKey.N.Cmp(reloadedKey.PrivateKey.N) != 0 {
		t.Error("RSA key changed after reopening database")
	}
}

func TestMissingKey(t *testing.T) {
	server := createTestServer(t)

	_, err := server.db.Exec("DELETE FROM keys")
	if err != nil {
		t.Fatal(err)
	}

	_, err = getKey(server.db, false)
	if !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("Expected sql.ErrNoRows, got %v", err)
	}
}

func TestInvalidPEM(t *testing.T) {
	_, err := loadKey(1, []byte("invalid-key"), time.Now().Unix())

	if err == nil {
		t.Error("Expected invalid PEM error")
	}
}

func TestInvalidRSAKey(t *testing.T) {
	_, err := loadKey(
		1,
		[]byte("-----BEGIN RSA PRIVATE KEY-----\nYWJj\n-----END RSA PRIVATE KEY-----"),
		time.Now().Unix(),
	)

	if err == nil {
		t.Error("Expected RSA parsing error")
	}
}

func TestJWKSDatabaseError(t *testing.T) {
	server := createTestServer(t)
	server.db.Close()

	request := httptest.NewRequest(
		http.MethodGet,
		"/.well-known/jwks.json",
		nil,
	)
	recorder := httptest.NewRecorder()

	server.jwksHandler(recorder, request)

	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500, got %d", recorder.Code)
	}
}

func TestAuthDatabaseError(t *testing.T) {
	server := createTestServer(t)
	server.db.Close()

	request := httptest.NewRequest(http.MethodPost, "/auth", nil)
	recorder := httptest.NewRecorder()

	server.authHandler(recorder, request)

	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500, got %d", recorder.Code)
	}
}

func TestPublicKeyToJWK(t *testing.T) {
	server := createTestServer(t)

	key, err := getKey(server.db, false)
	if err != nil {
		t.Fatal(err)
	}

	jwk := publicKeyToJWK(key)

	if jwk.Kid != key.Kid {
		t.Error("JWK kid does not match database key")
	}

	if jwk.N == "" || jwk.E == "" {
		t.Error("Missing public key components")
	}
}

func TestDatabaseKeyID(t *testing.T) {
	server := createTestServer(t)

	key, err := getKey(server.db, false)
	if err != nil {
		t.Fatal(err)
	}

	kid, err := strconv.ParseInt(key.Kid, 10, 64)
	if err != nil {
		t.Fatal(err)
	}

	if kid <= 0 {
		t.Error("Expected positive numeric key ID")
	}
}

func TestDatabaseFileExists(t *testing.T) {
	server := createTestServer(t)

	var dbPath string
	err := server.db.QueryRow("PRAGMA database_list").Scan(
		new(int), new(string), &dbPath,
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("SQLite database file missing: %v", err)
	}
}

func TestRSAKeySize(t *testing.T) {
	server := createTestServer(t)

	key, err := getKey(server.db, false)
	if err != nil {
		t.Fatal(err)
	}

	if key.PrivateKey.N.BitLen() != 2048 {
		t.Errorf("Expected 2048-bit RSA key, got %d",
			key.PrivateKey.N.BitLen())
	}
}

func TestRSAPublicKey(t *testing.T) {
	server := createTestServer(t)

	key, err := getKey(server.db, false)
	if err != nil {
		t.Fatal(err)
	}

	var publicKey *rsa.PublicKey = &key.PrivateKey.PublicKey

	if publicKey.E != 65537 {
		t.Errorf("Unexpected RSA exponent: %d", publicKey.E)
	}
}

func TestInitDB(t *testing.T) {
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	tempDir := t.TempDir()

	if err := os.Chdir(tempDir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(originalDir)

	db, err := initDB()
	if err != nil {
		t.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	if _, err := os.Stat(dbFile); err != nil {
		t.Fatalf("Database file was not created: %v", err)
	}

	var tableName string
	err = db.QueryRow(
		"SELECT name FROM sqlite_master WHERE type='table' AND name='keys'",
	).Scan(&tableName)

	if err != nil {
		t.Fatalf("Keys table was not created: %v", err)
	}

	if tableName != "keys" {
		t.Errorf("Expected keys table, got %s", tableName)
	}
}

func TestNewServer(t *testing.T) {
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	tempDir := t.TempDir()

	if err := os.Chdir(tempDir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(originalDir)

	server, err := NewServer()
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	var count int
	err = server.db.QueryRow(
		"SELECT COUNT(*) FROM keys",
	).Scan(&count)
	if err != nil {
		t.Fatal(err)
	}

	if count < 2 {
		t.Errorf("Expected at least 2 keys, got %d", count)
	}

	validKey, err := getKey(server.db, false)
	if err != nil {
		t.Fatalf("Valid key missing: %v", err)
	}

	expiredKey, err := getKey(server.db, true)
	if err != nil {
		t.Fatalf("Expired key missing: %v", err)
	}

	if validKey.Kid == expiredKey.Kid {
		t.Error("Valid and expired keys must have different IDs")
	}

	if err := server.db.Close(); err != nil {
		t.Fatal(err)
	}

	restartedServer, err := NewServer()
	if err != nil {
		t.Fatalf("Failed to restart server: %v", err)
	}
	defer restartedServer.db.Close()

	reloadedKey, err := getKey(restartedServer.db, false)
	if err != nil {
		t.Fatal(err)
	}

	if validKey.Kid != reloadedKey.Kid {
		t.Error("Valid key did not persist after restart")
	}
}
