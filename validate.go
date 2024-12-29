package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

func handleValidate(w http.ResponseWriter, r *http.Request) {
	accessTokenCookie, err := r.Cookie(accessTokenCookieName)
	if err == nil {
		accessTokenString := accessTokenCookie.Value
		_, err = verifyToken(accessTokenString)
		if err == nil {
			fmt.Fprintln(w, "Successfully authenticated")
			return
		}
	}

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
	appRedirectUrl := b.String()

	refreshTokenCookie, err := r.Cookie(refreshTokenCookieName)
	if err == nil {
		refreshTokenString := refreshTokenCookie.Value
		tokenSrc := oauth2Config.TokenSource(context.Background(), &oauth2.Token{
			AccessToken:  "dummy",
			TokenType:    "Bearer",
			RefreshToken: refreshTokenString,
			Expiry:       time.Unix(0, 0),
			ExpiresIn:    0,
		})
		newToken, err := tokenSrc.Token()
		if err != nil {
			log.Printf("Could not refresh token (err: %v)", err)
			unauthorized(w)
			return
		}

		accessToken, err := verifyToken(newToken.AccessToken)
		if err != nil {
			log.Printf("Refreshed token was unverified (err: %v)", err)
			unauthorized(w)
			return
		}

		expDate, err := accessToken.Claims.GetExpirationTime()
		if err != nil {
			log.Printf("Failed to get expiration date of refreshed token (err: %v)", err)
			unauthorized(w)
			return
		}

		cookie := tokenCookieWithExpires(accessTokenCookieName, newToken.AccessToken, expDate.Time)
		http.SetCookie(w, &cookie)

		if len(newToken.RefreshToken) > 0 {
			cookie := tokenCookieWithMaxAge(refreshTokenCookieName, newToken.RefreshToken, refreshTokenCookieMaxAge)
			http.SetCookie(w, &cookie)
		}

		http.Redirect(w, r, appRedirectUrl, http.StatusFound)
		return
	}

	url := oauth2Config.AuthCodeURL(appRedirectUrl)
	http.Redirect(w, r, url, http.StatusFound)
}
