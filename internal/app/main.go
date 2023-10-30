package main

import (
	"JWT/internal/config"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"time"
)

var (
	errTokenInvalid  = errors.New("токен недействительный")
	TokenFormatError = errors.New("неверный формат токена")
)

type UserClaims struct {
	ID       string    `json:"sub"`
	Username string    `json:"username"`
	Expired  time.Time `json:"expired"`
}

func (u *UserClaims) CreateToken(secretKey *config.JWT) (string, error) {
	const op = "Repo.JWT.CreateToken"

	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)

	claims["id"] = u.ID
	claims["username"] = u.Username
	claims["exp"] = u.Expired.Unix()

	tokenString, err := token.SignedString(secretKey.Key)
	if err != nil {
		return "", fmt.Errorf("%s,%w", op, err)
	}

	return tokenString, nil
}

func GetUserFromToken(secretKey *config.JWT, tokenString string) (*UserClaims, error) {
	const op = "Repo.JWT.GetUserFromToken"

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) { return secretKey.Key, nil })
	if err != nil {
		return nil, fmt.Errorf("%s,%w", op, err)
	}

	if token.Valid {
		userData, err := mapClaimsToUserClaims(token.Claims.(jwt.MapClaims))
		if err != nil {
			return nil, fmt.Errorf("%s,%w", op, err)
		}
		return userData, nil
	}

	return nil, errTokenInvalid
}

func mapClaimsToUserClaims(claims jwt.MapClaims) (*UserClaims, error) {
	const op = "Repo.JWT.mapClaimsToUserClaims"

	userID, userExists := claims["id"].(string)
	username, usernameExists := claims["username"].(string)

	if !userExists || !usernameExists {
		return nil, fmt.Errorf("%s,%w", op, errors.New("отсутствуют обезательные поля"))
	}

	user := &UserClaims{
		ID:       userID,
		Username: username,
	}

	return user, nil
}

func (u *UserClaims) AddValueToToken(secretKey *config.JWT, tokenString string, key string, value interface{}) (interface{}, error) {
	const op = "Repo.JWT.AddValueToToken"

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return secretKey.Key, nil
	})
	if err != nil {
		return "", fmt.Errorf("%s,%w", op, err)
	}

	if token.Valid {
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return "", fmt.Errorf("%s,%w", op, TokenFormatError)
		}

		claims[key] = value

		tokenString, err = token.SignedString(secretKey.Key)
		if err != nil {
			return "", fmt.Errorf("%s,%w", op, err)
		}

		return claims[key], nil
	}

	return "", errTokenInvalid
}

func main() {
	cfg := config.GetConfig()

	user := &UserClaims{
		ID:       "1",
		Username: "periskis",
		Expired:  time.Now().Add(time.Hour),
	}

	// Создаем токен
	token, err := user.CreateToken(cfg.JWT)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("Ваш JWT-токен:", token)
	}

	newToken, err := user.AddValueToToken(cfg.JWT, token, user.Username, "NEWperiskis")
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("Токен с добавленным значением:", newToken)
	}

	userData, err := GetUserFromToken(cfg.JWT, token)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("Данные токена:", userData)
	}
}
