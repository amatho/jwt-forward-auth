package main

import (
	"errors"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func unauthorized(w http.ResponseWriter) {
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

func redirectToAuth(w http.ResponseWriter, r *http.Request, appRedirectUrl string) {
	url := oauth2Config.AuthCodeURL(appRedirectUrl)
	http.Redirect(w, r, url, http.StatusFound)
}

func verifyToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, jwksKeyfunc.Keyfunc)
	if err != nil {
		return nil, errors.New("Invalid auth token")
	}

	_, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("Invalid claims")
	}

	return token, nil
}

func tokenCookieWithMaxAge(name string, value string, maxAge int) http.Cookie {
	cookie := tokenCookie(name, value)
	cookie.MaxAge = maxAge
	return cookie
}

func tokenCookieWithExpires(name string, value string, expires time.Time) http.Cookie {
	cookie := tokenCookie(name, value)
	cookie.Expires = expires
	return cookie
}

func clearAuthCookies(w http.ResponseWriter) {
	accessCookie := deleteTokenCookie(accessTokenCookieName)
	http.SetCookie(w, &accessCookie)
	refreshCookie := deleteTokenCookie(refreshTokenCookieName)
	http.SetCookie(w, &refreshCookie)
}

func deleteTokenCookie(name string) http.Cookie {
	cookie := tokenCookie(name, "")
	cookie.MaxAge = -1
	cookie.Expires = time.Unix(0, 0)
	return cookie
}

func tokenCookie(name string, value string) http.Cookie {
	cookie := http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	if len(cookieDomain) > 0 {
		cookie.Domain = cookieDomain
	}
	return cookie
}
