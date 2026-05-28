package license

import (
	"common/settings"
	"common/token"
	"fmt"
	"time"
)

var license_server_url = "https://licensing.author.io"
var community_token_path = "/.well-known/token/nvm.jwt"
var AccessToken *token.AccessToken

const temporaryTokenTTL = 5 * time.Minute

func Activate() error {
	cfg := settings.Global()
	tkn := cfg.AccessToken

	if tkn == "" {
		var err error
		tkn, err = fetchToken()
		if err != nil {
			if fallbackErr := useTemporaryToken(); fallbackErr != nil {
				return fmt.Errorf("Missing access token. Connect to the internet to obtain a free token or contact your system administrator for a commercial license: %w (temporary token fallback failed: %v)", err, fallbackErr)
			}
			return nil
		}

		if err := settings.Put("access_token", tkn); err != nil {
			return fmt.Errorf("Retrieved access token but failed to save it locally: %w", err)
		}
	}

	if err := token.Set(tkn); err != nil {
		if fallbackErr := useTemporaryToken(); fallbackErr != nil {
			return fmt.Errorf("Failed to parse access token: %w (temporary token fallback failed: %v)", err, fallbackErr)
		}
		return nil
	}

	AccessToken = token.Access

	if AccessToken.Expired() {
		tkn, fetchErr := fetchToken()
		if fetchErr != nil {
			if fallbackErr := useTemporaryToken(); fallbackErr != nil {
				return fmt.Errorf("Access token expired and failed to fetch a new one: %w (temporary token fallback failed: %v)", fetchErr, fallbackErr)
			}
			return nil
		}

		if err := token.Set(tkn); err != nil {
			if fallbackErr := useTemporaryToken(); fallbackErr != nil {
				return fmt.Errorf("Failed to parse access token: %w (temporary token fallback failed: %v)", err, fallbackErr)
			}
			return nil
		}

		if err := settings.Put("access_token", tkn); err != nil {
			return fmt.Errorf("Retrieved access token but failed to save it locally: %w", err)
		}

		AccessToken = token.Access
	}

	return nil
}

func useTemporaryToken() error {
	tmp, err := token.NewTemporaryToken(temporaryTokenTTL)
	if err != nil {
		return err
	}

	if err := settings.Put("access_token", tmp); err != nil {
		return err
	}

	if err := token.Set(tmp); err != nil {
		return err
	}

	AccessToken = token.Access
	return nil
}
