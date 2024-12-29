package main

import (
	"context"
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
		log.Printf("Failed to exchange token (err: %v)", err)
		unauthorized(w)
		return
	}

	accessTokenString := rawToken.AccessToken
	accessToken, err := verifyToken(accessTokenString)
	if err != nil {
		log.Printf("Could not verify token in callback (err: %v)", err)
		unauthorized(w)
		return
	}

	expDate, err := accessToken.Claims.GetExpirationTime()
	if err != nil {
		log.Printf("Failed to get token expiration date (err: %v)", err)
		unauthorized(w)
		return
	}

	cookie := tokenCookieWithExpires(accessTokenCookieName, accessTokenString, expDate.Time)
	http.SetCookie(w, &cookie)

	refreshTokenString := rawToken.RefreshToken
	if len(refreshTokenString) > 0 {
		cookie := tokenCookieWithMaxAge(refreshTokenCookieName, refreshTokenString, refreshTokenCookieMaxAge)
		http.SetCookie(w, &cookie)
	} else {
		log.Printf("Refresh token was empty")
	}

	url := state
	http.Redirect(w, r, url, http.StatusFound)
}
