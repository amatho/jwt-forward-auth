package main

import (
	"fmt"
	"log"
	"os"

	"github.com/MicahParks/keyfunc/v3"
)

type Config struct {
	jwksUrl string
	keyfunc keyfunc.Keyfunc
}

var config Config = Config{
	jwksUrl: requireEnv("AUTH_JWKS_URL"),
}

func init() {
	keyfunc, err := keyfunc.NewDefault([]string{config.jwksUrl})
	if err != nil {
		log.Fatalf("Failed to create keyfunc from %s.\nError: %s", config.jwksUrl, err)
	}
	config.keyfunc = keyfunc
}

func main() {
	fmt.Println("Hello world!")
}

func requireEnv(key string) string {
	value := os.Getenv(key)
	if len(value) == 0 {
		log.Fatalf("Missing environment variable '%s'", key)
	}
	return value
}
