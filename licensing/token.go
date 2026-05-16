package license

import (
	"common/settings"
	"common/token"
	"fmt"
)

var license_server_url = "https://licensing.author.io"
var community_token_path = "/.well-known/token/nvm.jwt"
var AccessToken *token.AccessToken

func Activate() error {
	cfg := settings.Global()
	tkn := cfg.AccessToken

	if tkn == "" {
		var err error
		tkn, err = fetchToken()
		if err != nil {
			return fmt.Errorf("Missing access token. Connect to the internet to obtain a free token or contact your system administrator for a commercial license: %w", err)
		}

		if err := settings.Put("access_token", tkn); err != nil {
			return fmt.Errorf("Retrieved access token but failed to save it locally: %w", err)
		}
	}

	if err := token.Set(tkn); err != nil {
		return fmt.Errorf("Failed to parse access token: %w", err)
	}

	AccessToken = token.Access

	if AccessToken.Expired() {
		tkn, fetchErr := fetchToken()
		if fetchErr != nil {
			if clearErr := settings.Del("access_token"); clearErr != nil {
				return fmt.Errorf("Access token expired and failed to fetch a new one: %w; additionally failed to clear cached token: %v", fetchErr, clearErr)
			}

			return fmt.Errorf("Access token expired and failed to fetch a new one: %w", fetchErr)
		}

		if err := token.Set(tkn); err != nil {
			return fmt.Errorf("Failed to parse access token: %w", err)
		}

		AccessToken = token.Access
	}

	return nil
}
