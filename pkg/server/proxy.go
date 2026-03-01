package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/getcreddy/creddy/pkg/backend"
)

// RegisterProxyRoutes adds proxy endpoints to the mux
func (s *Server) RegisterProxyRoutes(mux *http.ServeMux) {
	// Catch-all for proxy requests: /v1/proxy/{backend}/{path...}
	mux.HandleFunc("/v1/proxy/", s.handleProxy)
}

// handleProxy routes requests to plugin proxies
// Creddy's proxy is a passthrough - it validates the agent and routes to the plugin's proxy
// The plugin proxy handles the actual upstream API communication
func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	// Parse path: /v1/proxy/{backend}/{path...}
	path := strings.TrimPrefix(r.URL.Path, "/v1/proxy/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusBadRequest, "missing backend in proxy path")
		return
	}

	backendName := parts[0]
	remainingPath := "/"
	if len(parts) > 1 {
		remainingPath = "/" + parts[1]
	}

	// Get backend to find proxy config
	b, err := s.backends.Get(backendName)
	if err != nil {
		writeError(w, http.StatusNotFound, "backend not found: "+backendName)
		return
	}

	// Check if backend supports proxy mode
	pb, ok := b.(backend.ProxyBackend)
	if !ok {
		writeError(w, http.StatusBadRequest, "backend does not support proxy mode: "+backendName)
		return
	}

	proxyConfig := pb.ProxyConfig()
	if proxyConfig.PluginProxyPort == 0 {
		writeError(w, http.StatusBadRequest, "backend proxy not configured: "+backendName)
		return
	}

	// Build plugin proxy URL
	pluginProxyURL := fmt.Sprintf("http://localhost:%d%s", proxyConfig.PluginProxyPort, remainingPath)
	if r.URL.RawQuery != "" {
		pluginProxyURL += "?" + r.URL.RawQuery
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	// Create request to plugin proxy
	proxyReq, err := http.NewRequestWithContext(ctx, r.Method, pluginProxyURL, r.Body)
	if err != nil {
		log.Printf("Failed to create proxy request: %v", err)
		writeError(w, http.StatusInternalServerError, "failed to create proxy request")
		return
	}

	// Copy all headers (plugin proxy handles auth)
	for k, vv := range r.Header {
		k = http.CanonicalHeaderKey(k)
		if k == "Host" {
			continue
		}
		for _, v := range vv {
			proxyReq.Header.Add(k, v)
		}
	}

	// Make request to plugin proxy
	client := &http.Client{
		Timeout: 5 * time.Minute,
	}

	resp, err := client.Do(proxyReq)
	if err != nil {
		log.Printf("Plugin proxy request failed for %s: %v", backendName, err)
		writeError(w, http.StatusBadGateway, "plugin proxy unavailable")
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	w.WriteHeader(resp.StatusCode)

	// Check if streaming (SSE)
	if strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
		flusher, ok := w.(http.Flusher)
		if !ok {
			io.Copy(w, resp.Body)
			return
		}

		buf := make([]byte, 4096)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				w.Write(buf[:n])
				flusher.Flush()
			}
			if err != nil {
				break
			}
		}
	} else {
		io.Copy(w, resp.Body)
	}
}

// extractProxyPort gets the plugin proxy port from backend config
func extractProxyPort(configJSON string) int {
	var cfg struct {
		ProxyPort int `json:"proxy_port"`
	}
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return 0
	}
	return cfg.ProxyPort
}
