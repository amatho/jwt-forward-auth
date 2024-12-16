package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
)

func handleCallback(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	state := query.Get("state")
	code := query.Get("code")

	if len(state) == 0 {
		http.Error(w, "Missing state in callback request", http.StatusBadRequest)
		return
	}

	rawToken, err := oauth2Config.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	tokenString := rawToken.AccessToken
	token, err := verifyToken(tokenString)
	if err != nil {
		log.Printf("Could not verify token in callback (error: %v)", err)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	expDate, err := token.Claims.GetExpirationTime()
	if err != nil {
		http.Error(w, "Failed to get token expiration date: "+err.Error(), http.StatusInternalServerError)
		return
	}

	cookie := http.Cookie{
		Name:     cookieName,
		Value:    tokenString,
		Path:     "/",
		Expires:  expDate.Time,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, &cookie)

	url := state
	fmt.Fprintf(w, "Successfully authenticated.\nRedirect would be to: %v", url)
}
