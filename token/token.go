package token

import "github.com/golang-jwt/jwt/v5"

var Access *AccessToken

type TokenClaims struct {
	jwt.RegisteredClaims
	Plan  string   `json:"plan"`
	Roles []string `json:"roles"`
}

func Set(raw string) error {
	token, _, err := jwt.NewParser().ParseUnverified(raw, &TokenClaims{})
	if err != nil {
		return err
	}

	Access = &AccessToken{Token: token}

	return nil
}
