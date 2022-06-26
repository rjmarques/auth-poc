package main

import (
	"fmt"
	"os"

	"github.com/rjmarques/auth-poc/keycloak/auth"
	"github.com/rjmarques/auth-poc/keycloak/server"
)

func main() {
	keycloakURL := os.Getenv("KEYCLOAK_URL")
	appName := os.Getenv("APP_NAME")
	appSecret := os.Getenv("APP_SECRET")
	realm := os.Getenv("REALM")
	port := os.Getenv("PORT")

	authProvider := auth.NewAuth(keycloakURL, appName, appSecret, realm)

	s := server.NewServer(port, authProvider)
	fmt.Printf("starting server on :%s\n", port)
	panic(s.Listen())
}
