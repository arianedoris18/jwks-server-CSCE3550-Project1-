package main

import (
	"log"
	"net/http"
)

func main() {
	server, err := NewServer()
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	log.Println("JWKS server running on http://localhost:8080")

	err = http.ListenAndServe(":8080", server.routes())
	if err != nil {
		log.Fatal(err)
	}
}
