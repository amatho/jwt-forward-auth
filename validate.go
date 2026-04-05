package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

func handleValidate(w http.ResponseWriter, r *http.Request) {
	logRequest(r)

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

	path := strings.TrimPrefix(r.RequestURI, "/check")

	b := new(strings.Builder)
	b.WriteString(scheme)
	b.WriteString("://")
	b.WriteString(r.Host)
	b.WriteString(path)
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
			logger.Error("Could not refresh token", "error", err)
			clearCookiesAndRedirectToAuth(w, r, appRedirectUrl)
			return
		}

		accessToken, err := verifyToken(newToken.AccessToken)
		if err != nil {
			logger.Error("Refreshed token was unverified", "error", err)
			clearCookiesAndRedirectToAuth(w, r, appRedirectUrl)
			return
		}

		expDate, err := accessToken.Claims.GetExpirationTime()
		if err != nil {
			logger.Error("Failed to get expiration date of refreshed token", "error", err)
			clearCookiesAndRedirectToAuth(w, r, appRedirectUrl)
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

	redirectToAuth(w, r, appRedirectUrl)
}

func logRequest(r *http.Request) {
	sanitizedHeader := r.Header.Clone()
	sanitizedHeader.Del("Cookie")
	sanitizedHeader.Del("Authorization")
	logger.Info("Validating request", "method", r.Method, "url", r.URL.String(), "headers", fmt.Sprint(sanitizedHeader))
}
