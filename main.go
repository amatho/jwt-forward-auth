package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/coreos/go-oidc"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
)

var oauth2Config oauth2.Config
var jwksKeyfunc keyfunc.Keyfunc
var callbackURL string

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Printf("Could not load .env file (%s)", err)
	}

	clientID := requireEnv("CLIENT_ID")
	clientSecret := requireEnv("CLIENT_SECRET")
	redirectURL := requireEnv("REDIRECT_URL")
	issuerURL := requireEnv("ISSUER_URL")

	provider, err := oidc.NewProvider(context.Background(), issuerURL)
	if err != nil {
		log.Fatalf("Failed to create OIDC provider: %v", err)
	}

	log.Printf("Provider endpoint: %q", provider.Endpoint())
	oauth2Config = oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
	}

	jwksUrl := issuerURL + "/.well-known/jwks.json"
	keyfunc, err := keyfunc.NewDefault([]string{jwksUrl})
	if err != nil {
		log.Fatalf("Failed to create keyfunc from %s.\nError: %s", jwksUrl, err)
	}
	jwksKeyfunc = keyfunc

	http.HandleFunc("/", handleValidate)
	http.HandleFunc("/callback", handleCallback)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func requireEnv(key string) string {
	value := os.Getenv(key)
	if len(value) == 0 {
		log.Fatalf("Missing environment variable '%s'", key)
	}
	return value
}
