package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
)

func handleValidate(w http.ResponseWriter, r *http.Request) {
	accessTokenCookie, err := r.Cookie(cookieName)
	if err != nil {
		log.Printf("Could not get access token (err: %v)", err)

		scheme := r.Header.Get("X-Forwarded-Proto")
		if len(scheme) == 0 {
			http.Error(w, "Missing 'X-Forwarded-Proto' header", http.StatusBadRequest)
			return
		}

		host := r.Header.Get("X-Forwarded-Host")
		if len(host) == 0 {
			http.Error(w, "Missing 'X-Forwarded-Host' header", http.StatusBadRequest)
			return
		}

		redirectUri := r.Header.Get("X-Forwarded-Uri")
		if len(redirectUri) == 0 {
			http.Error(w, "Missing 'X-Forwarded-Uri' header", http.StatusBadRequest)
			return
		}

		b := new(strings.Builder)
		b.WriteString(scheme)
		b.WriteString("://")
		b.WriteString(host)
		b.WriteString(redirectUri)
		state := b.String()

		url := oauth2Config.AuthCodeURL(state)
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
