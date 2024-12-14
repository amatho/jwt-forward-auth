package main

import (
	"errors"

	"github.com/golang-jwt/jwt/v5"
)

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
