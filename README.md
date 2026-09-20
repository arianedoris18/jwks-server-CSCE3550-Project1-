# JWKS Server

A RESTful JSON Web Key Set (JWKS) server implemented in **Go** for CSCE 3550.

The server generates RSA key pairs, assigns unique Key IDs (`kid`), manages key expiration, serves valid public keys through a JWKS endpoint, and issues signed JSON Web Tokens (JWTs).

## Features

* Generates RSA public/private key pairs
* Assigns a unique `kid` to each key
* Tracks key expiration
* Serves public keys in JWKS format
* Excludes expired keys from the JWKS endpoint
* Issues JWTs signed using RS256
* Includes the signing key's `kid` in the JWT header
* Supports issuing an intentionally expired JWT for testing
* Uses appropriate HTTP methods and status codes
* Runs on port `8080`

## Technologies

* Go
* Go `net/http`
* Go `crypto/rsa`
* Go `crypto/rand`
* `github.com/golang-jwt/jwt/v5`
* JSON Web Tokens (JWT)
* JSON Web Keys (JWK/JWKS)
* RSA / RS256

## Project Structure

```text
jwks-server/
├── go.mod
├── go.sum
├── main.go
├── server.go
├── server_test.go
├── README.md
└── screenshots/
    ├── gradebot.png
    └── coverage.png
```

## API Endpoints

### GET `/.well-known/jwks.json`

Returns the server's currently valid public keys in JWKS format.

Expired keys are not returned.

Example:

```bash
curl http://localhost:8080/.well-known/jwks.json
```

Example response:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "valid-key",
      "alg": "RS256",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

### POST `/auth`

Creates and returns a signed JWT using the current valid RSA private key.

Example:

```bash
curl -X POST http://localhost:8080/auth
```

The JWT header contains the `kid` of the key used to sign the token.

Example decoded header:

```json
{
  "alg": "RS256",
  "kid": "valid-key",
  "typ": "JWT"
}
```

### POST `/auth?expired=true`

Creates an intentionally expired JWT signed using the expired RSA private key.

Example:

```bash
curl -X POST "http://localhost:8080/auth?expired=true"
```

Example decoded JWT header:

```json
{
  "alg": "RS256",
  "kid": "expired-key",
  "typ": "JWT"
}
```

The token's `exp` claim is set to a time in the past.

The expired public key is not returned from `/.well-known/jwks.json`.

## Running the Server

### Requirements

Install Go and download the project's dependencies.

```bash
go mod download
```

### Start the Server

From the project directory:

```bash
go run .
```

The application will start on:

```text
http://localhost:8080
```

## Testing

Run the automated test suite with:

```bash
go test ./...
```

Run the tests with code coverage:

```bash
go test -cover
```

A detailed HTML coverage report can be generated with:

```bash
go test -coverprofile=coverage.out
go tool cover -html=coverage.out
```

The project targets more than **80% test coverage**.

## Formatting and Code Quality

Format the Go source code with:

```bash
gofmt -w .
```

Check the project for potential Go issues with:

```bash
go vet ./...
```

## Black-Box Testing

The project was tested using the provided CSCE 3550 Gradebot.

Example command:

```bash
gradebot project-1 --dir="." --run="go run ." --port=8080
```

The server successfully passed the functional Gradebot tests for:

* Valid JWT authentication
* Expired JWT authentication
* Proper HTTP methods and status codes
* Valid JWK availability
* JWT expiration
* Exclusion of expired JWKs from the JWKS endpoint

## Gradebot Result

The functional Gradebot run produced a score of **92.86%**.

The code-quality portion reported:

```text
Connect call failed: internal: failed to review code
```

The server functionality tests themselves passed.

A screenshot of the Gradebot results is included in the repository.

## Screenshots

### Gradebot

Add the Gradebot screenshot to:

```text
screenshots/gradebot.png
```

Then it can be displayed here with:

```markdown
![Gradebot Results](screenshots/gradebot.png)
```

### Test Coverage

Add the test coverage screenshot to:

```text
screenshots/coverage.png
```

Then it can be displayed here with:

```markdown
![Test Coverage](screenshots/coverage.png)
```

## Key Expiration

The server creates two RSA key pairs:

* **Valid key:** expires in the future and is included in the JWKS endpoint.
* **Expired key:** has an expiration timestamp in the past and is excluded from the JWKS endpoint.

When `/auth` is called normally, the valid key signs the JWT.

When the `expired` query parameter is present, the expired key signs the JWT and the token receives an expiration time in the past.

## Purpose

This project was created for educational purposes to demonstrate:

* RESTful HTTP services
* RSA public/private key cryptography
* JSON Web Tokens
* JSON Web Keys
* JSON Web Key Sets
* Key IDs (`kid`)
* Key expiration
* JWT signature verification

This implementation is intended for coursework and is not designed to serve as a production authentication system.

## Author

**Ariane Doris Umuhire**

CSCE 3550
