package token

import (
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type AccessToken struct {
	*jwt.Token
}

func (t *AccessToken) Expired() bool {
	exp, err := t.Claims.(*TokenClaims).GetExpirationTime()
	if err != nil {
		return true
	}

	return exp.Before(time.Now())
}

func (t *AccessToken) Type() string {
	claims, ok := t.Claims.(*TokenClaims)
	if !ok || claims == nil {
		return "community"
	}

	res := claims.PrimaryEntitlement()
	switch strings.ToLower(res) {
	case EntitlementCommunity, "":
		return EntitlementCommunity
	default:
		if t.Valid {
			return res
		}
		return EntitlementCommunity
	}
}
