package main

import (
	"log"
	"net/http"
	"strings"
)

func handleValidate(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	tokenString, found := strings.CutPrefix(authHeader, "Bearer ")
	if !found {
		log.Printf("No auth token (value: %q)", authHeader)
		state := "state"
		url := oauth2Config.AuthCodeURL(state)
		http.Redirect(w, r, url, http.StatusFound)
		return
	}

	_, err := verifyToken(tokenString)
	if err != nil {
		log.Printf("Could not verify token (error: %v)", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
	}

	w.WriteHeader(http.StatusNoContent)
}
