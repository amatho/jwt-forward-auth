package main

import (
	"context"
	"fmt"
	"net/http"
)

func handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	rawToken, err := oauth2Config.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	tokenString := rawToken.AccessToken
	_, err = verifyToken(tokenString)

	fmt.Fprintf(w, "Received callback with query: %#v\nAccess token: %q", r.URL.Query(), tokenString)
}
