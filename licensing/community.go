package license

import (
	"common/http"
	"fmt"
	"io"
	"strings"
)

func fetchToken() (string, error) {
	tokenURL := strings.TrimRight(license_server_url, "/") + community_token_path
	resp, err := http.GET(tokenURL)
	if err != nil {
		return "", fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("download failed with status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	token := strings.TrimSpace(string(body))
	if token == "" {
		return "", fmt.Errorf("download returned an empty token")
	}

	return token, nil
}
