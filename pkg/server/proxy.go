package server

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/getcreddy/creddy/pkg/backend"
)

// proxyCredentialCache caches credentials per agent/backend to avoid
// creating a new credential for every proxied request
type proxyCredentialCache struct {
	mu    sync.RWMutex
	cache map[string]*cachedCred
}

type cachedCred struct {
	token     string
	expiresAt time.Time
}

var credCache = &proxyCredentialCache{
	cache: make(map[string]*cachedCred),
}

func (c *proxyCredentialCache) get(key string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	cred, ok := c.cache[key]
	if !ok {
		return "", false
	}
	
	// Check if expired (with 30s buffer)
	if time.Now().Add(30 * time.Second).After(cred.expiresAt) {
		return "", false
	}
	
	return cred.token, true
}

func (c *proxyCredentialCache) set(key, token string, expiresAt time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.cache[key] = &cachedCred{
		token:     token,
		expiresAt: expiresAt,
	}
}

// RegisterProxyRoutes adds proxy endpoints to the mux
func (s *Server) RegisterProxyRoutes(mux *http.ServeMux) {
	// Catch-all for proxy requests: /v1/proxy/{backend}/{path...}
	mux.HandleFunc("/v1/proxy/", s.handleProxy)
}

// handleProxy handles all proxy requests
func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	// Parse path: /v1/proxy/{backend}/{path...}
	path := strings.TrimPrefix(r.URL.Path, "/v1/proxy/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusBadRequest, "missing backend in proxy path")
		return
	}
	
	backendName := parts[0]
	upstreamPath := ""
	if len(parts) > 1 {
		upstreamPath = "/" + parts[1]
	}
	
	// Validate agent token
	token := extractBearerToken(r)
	if token == "" {
		// Also check x-api-key header (common for AI APIs)
		token = r.Header.Get("x-api-key")
	}
	if token == "" {
		writeError(w, http.StatusUnauthorized, "missing authorization")
		return
	}
	
	agent, err := s.store.GetAgentByTokenHash(hashToken(token))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid agent token")
		return
	}
	
	// Check agent has permission for this backend
	if !agentCanAccessBackend(agent, backendName, nil, nil, false) {
		writeError(w, http.StatusForbidden, "agent not authorized for backend: "+backendName)
		return
	}
	
	// Get backend
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
	if proxyConfig.UpstreamURL == "" {
		writeError(w, http.StatusInternalServerError, "backend proxy not configured")
		return
	}
	
	// Get or create credential for this agent/backend
	cacheKey := fmt.Sprintf("%s:%s", agent.ID, backendName)
	credential, ok := credCache.get(cacheKey)
	if !ok {
		// Create new credential
		tokenReq := backend.TokenRequest{
			TTL: 10 * time.Minute,
		}
		
		cred, err := b.GetToken(tokenReq)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to get credential: "+err.Error())
			return
		}
		
		credential = cred.Value
		credCache.set(cacheKey, cred.Value, cred.ExpiresAt)
		
		// Record credential issuance
		s.store.CreateActiveCredential(agent.ID, backendName, hashToken(cred.Value), "", "proxy", cred.ExpiresAt)
		s.store.UpdateAgentLastUsed(agent.ID)
	}
	
	// Build upstream request
	upstreamURL := proxyConfig.UpstreamURL + upstreamPath
	if r.URL.RawQuery != "" {
		upstreamURL += "?" + r.URL.RawQuery
	}
	
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	
	upstreamReq, err := http.NewRequestWithContext(ctx, r.Method, upstreamURL, r.Body)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create upstream request")
		return
	}
	
	// Copy headers (except auth headers we'll set ourselves)
	for k, vv := range r.Header {
		k = http.CanonicalHeaderKey(k)
		if k == "Authorization" || k == "X-Api-Key" || k == "Host" {
			continue
		}
		for _, v := range vv {
			upstreamReq.Header.Add(k, v)
		}
	}
	
	// Set credential header
	headerName := proxyConfig.HeaderName
	if headerName == "" {
		headerName = "Authorization"
	}
	headerValue := credential
	if proxyConfig.HeaderPrefix != "" {
		headerValue = proxyConfig.HeaderPrefix + credential
	}
	upstreamReq.Header.Set(headerName, headerValue)
	
	// Make request
	client := &http.Client{
		Timeout: 5 * time.Minute,
	}
	
	resp, err := client.Do(upstreamReq)
	if err != nil {
		log.Printf("Proxy error for %s: %v", backendName, err)
		writeError(w, http.StatusBadGateway, "upstream request failed")
		return
	}
	defer resp.Body.Close()
	
	// Copy response headers
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	
	// Check if this is a streaming response (SSE)
	isStreaming := strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream")
	
	w.WriteHeader(resp.StatusCode)
	
	if isStreaming {
		// Stream the response with flushing
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
