package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestJWKSReturnsValidKey(t *testing.T) {
	server, err := NewServer()
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	request := httptest.NewRequest(
		http.MethodGet,
		"/.well-known/jwks.json",
		nil,
	)

	recorder := httptest.NewRecorder()

	server.jwksHandler(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", recorder.Code)
	}

	var jwks JWKS

	err = json.Unmarshal(recorder.Body.Bytes(), &jwks)
	if err != nil {
		t.Fatalf("Failed to parse JWKS: %v", err)
	}

	if len(jwks.Keys) != 1 {
		t.Fatalf("Expected 1 valid key, got %d", len(jwks.Keys))
	}

	if jwks.Keys[0].Kid != "valid-key" {
		t.Errorf("Expected valid-key, got %s", jwks.Keys[0].Kid)
	}
}

func TestJWKSDoesNotReturnExpiredKey(t *testing.T) {
	server, err := NewServer()
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	request := httptest.NewRequest(
		http.MethodGet,
		"/.well-known/jwks.json",
		nil,
	)

	recorder := httptest.NewRecorder()

	server.jwksHandler(recorder, request)

	if strings.Contains(recorder.Body.String(), "expired-key") {
		t.Error("JWKS should not contain expired keys")
	}
}

func TestJWKSRejectsPost(t *testing.T) {
	server, _ := NewServer()

	request := httptest.NewRequest(
		http.MethodPost,
		"/.well-known/jwks.json",
		nil,
	)

	recorder := httptest.NewRecorder()

	server.jwksHandler(recorder, request)

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Errorf(
			"Expected status 405, got %d",
			recorder.Code,
		)
	}
}

func TestAuthReturnsJWT(t *testing.T) {
	server, _ := NewServer()

	request := httptest.NewRequest(
		http.MethodPost,
		"/auth",
		nil,
	)

	recorder := httptest.NewRecorder()

	server.authHandler(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", recorder.Code)
	}

	tokenString := recorder.Body.String()

	if tokenString == "" {
		t.Fatal("Expected JWT but received empty response")
	}

	token, err := jwt.Parse(
		tokenString,
		func(token *jwt.Token) (interface{}, error) {
			return &server.validKey.PrivateKey.PublicKey, nil
		},
	)

	if err != nil {
		t.Fatalf("Failed to verify JWT: %v", err)
	}

	if !token.Valid {
		t.Error("Expected valid JWT")
	}

	if token.Header["kid"] != "valid-key" {
		t.Errorf(
			"Expected kid valid-key, got %v",
			token.Header["kid"],
		)
	}
}

func TestExpiredAuthReturnsExpiredJWT(t *testing.T) {
	server, _ := NewServer()

	request := httptest.NewRequest(
		http.MethodPost,
		"/auth?expired=true",
		nil,
	)

	recorder := httptest.NewRecorder()

	server.authHandler(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", recorder.Code)
	}

	tokenString := recorder.Body.String()

	parser := jwt.NewParser(
		jwt.WithoutClaimsValidation(),
	)

	token, err := parser.Parse(
		tokenString,
		func(token *jwt.Token) (interface{}, error) {
			return &server.expiredKey.PrivateKey.PublicKey, nil
		},
	)

	if err != nil {
		t.Fatalf("Failed to parse expired JWT: %v", err)
	}

	if token.Header["kid"] != "expired-key" {
		t.Errorf(
			"Expected expired-key, got %v",
			token.Header["kid"],
		)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("Could not read claims")
	}

	exp, err := claims.GetExpirationTime()
	if err != nil {
		t.Fatalf("Could not read expiration: %v", err)
	}

	if !exp.Before(time.Now()) {
		t.Error("Expected token to be expired")
	}
}

func TestAuthRejectsGet(t *testing.T) {
	server, _ := NewServer()

	request := httptest.NewRequest(
		http.MethodGet,
		"/auth",
		nil,
	)

	recorder := httptest.NewRecorder()

	server.authHandler(recorder, request)

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Errorf(
			"Expected status 405, got %d",
			recorder.Code,
		)
	}
}

func TestRoutes(t *testing.T) {
	server, _ := NewServer()

	testServer := httptest.NewServer(server.routes())
	defer testServer.Close()

	response, err := http.Get(
		testServer.URL + "/.well-known/jwks.json",
	)

	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	defer response.Body.Close()

	body, _ := io.ReadAll(response.Body)

	if response.StatusCode != http.StatusOK {
		t.Errorf(
			"Expected 200, got %d. Body: %s",
			response.StatusCode,
			string(body),
		)
	}
}
