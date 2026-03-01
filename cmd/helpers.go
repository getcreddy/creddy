package cmd

import (
	"net/http"
	"time"

	"github.com/spf13/viper"
)

// detectLocalServer checks if a creddy server is running locally
func detectLocalServer() string {
	localURLs := []string{
		"http://127.0.0.1:8400",
		"http://localhost:8400",
	}

	client := &http.Client{Timeout: 2 * time.Second}
	for _, url := range localURLs {
		resp, err := client.Get(url + "/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return url
			}
		}
	}
	return ""
}

// getServerURL returns the server URL from flags, env, config, or local detection
func getServerURL(flagValue string) string {
	// 1. Explicit flag
	if flagValue != "" {
		return flagValue
	}

	// 2. Config/env (viper handles both)
	if url := viper.GetString("url"); url != "" {
		return url
	}

	// 3. Try localhost
	if url := detectLocalServer(); url != "" {
		return url
	}

	return ""
}
