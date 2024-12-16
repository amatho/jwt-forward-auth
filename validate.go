package main

import (
	"fmt"
	"log"
	"net/http"
)

func handleValidate(w http.ResponseWriter, r *http.Request) {
	accessTokenCookie, err := r.Cookie(cookieName)
	if err != nil {
		redirectUri := r.Header.Get("X-Forwarded-Uri")
		if len(redirectUri) == 0 {
			http.Error(w, "Missing 'X-Forwarded-Uri' header", http.StatusBadRequest)
			return
		}

		url := oauth2Config.AuthCodeURL(redirectUri)
		http.Redirect(w, r, url, http.StatusFound)
		return
	}

	tokenString := accessTokenCookie.Value
	_, err = verifyToken(tokenString)
	if err != nil {
		log.Printf("Could not validate token (error: %v)", err)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	fmt.Fprintln(w, "Successfully authenticated")
}
