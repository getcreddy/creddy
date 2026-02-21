package client

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

const (
	HeaderClientID   = "X-Creddy-Client"
	HeaderTimestamp  = "X-Creddy-Timestamp"
	HeaderSignature  = "X-Creddy-Signature"
	
	// MaxTimestampSkew is the maximum allowed time difference between client and server
	MaxTimestampSkew = 5 * time.Minute
)

// SignRequest signs an HTTP request with the client's private key
func (c *Client) SignRequest(req *http.Request, body []byte) error {
	timestamp := time.Now().Unix()
	
	// Build the message to sign: client_id + timestamp + method + path + body_hash
	bodyHash := sha256.Sum256(body)
	message := fmt.Sprintf("%s\n%d\n%s\n%s\n%s",
		c.ID,
		timestamp,
		req.Method,
		req.URL.Path,
		base64.StdEncoding.EncodeToString(bodyHash[:]),
	)
	
	signature := ed25519.Sign(c.PrivateKey, []byte(message))
	
	req.Header.Set(HeaderClientID, c.ID)
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(timestamp, 10))
	req.Header.Set(HeaderSignature, base64.StdEncoding.EncodeToString(signature))
	
	return nil
}

// VerifyRequest verifies a signed HTTP request
func VerifyRequest(req *http.Request, body []byte, publicKey ed25519.PublicKey, clientID string) error {
	gotClientID := req.Header.Get(HeaderClientID)
	if gotClientID != clientID {
		return fmt.Errorf("client ID mismatch")
	}
	
	timestampStr := req.Header.Get(HeaderTimestamp)
	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timestamp: %w", err)
	}
	
	// Check timestamp is within acceptable range
	now := time.Now().Unix()
	if abs(now-timestamp) > int64(MaxTimestampSkew.Seconds()) {
		return fmt.Errorf("timestamp too far from server time")
	}
	
	signatureStr := req.Header.Get(HeaderSignature)
	signature, err := base64.StdEncoding.DecodeString(signatureStr)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}
	
	// Reconstruct the message
	bodyHash := sha256.Sum256(body)
	message := fmt.Sprintf("%s\n%d\n%s\n%s\n%s",
		clientID,
		timestamp,
		req.Method,
		req.URL.Path,
		base64.StdEncoding.EncodeToString(bodyHash[:]),
	)
	
	if !ed25519.Verify(publicKey, []byte(message), signature) {
		return fmt.Errorf("signature verification failed")
	}
	
	return nil
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}
