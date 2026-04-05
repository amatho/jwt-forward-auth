package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/coreos/go-oidc"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
)

var (
	logger                   = slog.New(slog.NewJSONHandler(os.Stderr, nil))
	oauth2Config             oauth2.Config
	jwksKeyfunc              keyfunc.Keyfunc
	cookieDomain             string
	accessTokenCookieName    string = "accessToken"
	refreshTokenCookieName   string = "refreshToken"
	refreshTokenCookieMaxAge int
)

func main() {
	err := godotenv.Load()
	if err != nil {
		logger.Debug(fmt.Sprintf("Could not load .env file (%s)", err))
	}

	clientID := requireEnv("CLIENT_ID")
	clientSecret := requireEnv("CLIENT_SECRET")
	redirectURL := requireEnv("REDIRECT_URL")
	issuerURL := requireEnv("ISSUER_URL")
	cookieDomain = os.Getenv("COOKIE_DOMAIN")
	refreshTokenExpiresSeconds := requireEnv("REFRESH_TOKEN_EXPIRES_SECONDS")
	refreshTokenCookieMaxAge, err = strconv.Atoi(refreshTokenExpiresSeconds)
	if err != nil {
		logger.Error(fmt.Sprintf("Could not parse refresh token expiration (in seconds) as an integer (value: %q)",
			refreshTokenExpiresSeconds))
	}

	provider, err := oidc.NewProvider(context.Background(), issuerURL)
	if err != nil {
		logger.Error("Failed to create OIDC provider", "error", err)
		os.Exit(1)
	}

	logger.Info(fmt.Sprintf("Provider endpoint: %q", provider.Endpoint()))
	oauth2Config = oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
	}

	jwksUrl := issuerURL + "/.well-known/jwks.json"
	keyfunc, err := keyfunc.NewDefault([]string{jwksUrl})
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to create keyfunc from %s", jwksUrl), "error", err)
		os.Exit(1)
	}
	jwksKeyfunc = keyfunc

	http.HandleFunc("/check", handleValidate)
	http.HandleFunc("/check/", handleValidate)
	http.HandleFunc("/callback", handleCallback)
	logger.Info(http.ListenAndServe(":8080", nil).Error())
	os.Exit(0)
}

func requireEnv(key string) string {
	value := os.Getenv(key)
	if len(value) == 0 {
		logger.Error(fmt.Sprintf("Missing environment variable '%s'", key))
		os.Exit(1)
	}
	return value
}
