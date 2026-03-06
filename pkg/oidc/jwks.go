package oidc

import (
	"encoding/json"
	"net/http"
)

// JWKSHandler returns an HTTP handler for the JWKS endpoint
func (km *KeyManager) JWKSHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600") // Cache for 1 hour
		
		jwks := km.JWKS()
		json.NewEncoder(w).Encode(jwks)
	}
}
