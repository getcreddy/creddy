# OIDC Provider Guide

Creddy can act as an OpenID Connect (OIDC) provider, allowing agents to authenticate using standard OAuth 2.0 flows and obtain JWT-based identity tokens.

## Quick Start

### 1. Enable OIDC

Start the server with an OIDC issuer URL:

```bash
creddy server --oidc-issuer https://creddy.example.com
```

Or in your config file:

```yaml
oidc:
  issuer: https://creddy.example.com
```

### 2. Create an Agent

```bash
creddy agent create my-agent --scopes github:owner/repo
```

Output:
```json
{
  "id": "abc-123",
  "name": "my-agent",
  "token": "ckr_xxx...",
  "oidc": {
    "client_id": "agent_abc123",
    "client_secret": "cks_xxx..."
  }
}
```

Save both the vend token and OIDC credentials.

### 3. Get Access Token

```bash
curl -X POST https://creddy.example.com/oauth/token \
  -d "grant_type=client_credentials" \
  -d "client_id=agent_abc123" \
  -d "client_secret=cks_xxx" \
  -d "scope=openid github"
```

Response:
```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "id_token": "eyJ..."
}
```

### 4. Use Access Token

```bash
# Get ephemeral GitHub token
curl https://creddy.example.com/v1/credentials/github \
  -H "Authorization: Bearer eyJ..."

# Check agent status
curl https://creddy.example.com/v1/status \
  -H "Authorization: Bearer eyJ..."
```

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /.well-known/openid-configuration` | OIDC discovery document |
| `GET /.well-known/jwks.json` | JSON Web Key Set |
| `POST /oauth/token` | Token endpoint |
| `GET /oauth/userinfo` | Agent info (requires access token) |

## Token Types

### Access Token

A JWT used to authenticate API requests. Contains:
- `sub`: Agent ID
- `agent_id`: Same as sub
- `scopes`: Array of granted scopes
- `exp`: Expiration time

### ID Token

A JWT containing agent identity claims:
- All access token claims, plus:
- `agent_name`: Human-readable name
- `auth_time`: When agent authenticated
- Standard OIDC claims (`iss`, `aud`, etc.)

## Authentication Methods

Both methods are supported for backward compatibility:

### OIDC (Recommended)

```bash
# Get token first
TOKEN=$(curl -s -X POST https://creddy.example.com/oauth/token \
  -d "grant_type=client_credentials" \
  -d "client_id=agent_abc123" \
  -d "client_secret=cks_xxx" \
  | jq -r .access_token)

# Use token
curl -H "Authorization: Bearer $TOKEN" ...
```

### Vend

```bash
# Use vend token directly (no OAuth exchange)
curl -H "Authorization: Bearer ckr_xxx" ...
```

## Key Rotation

OIDC signing keys can be rotated without downtime:

```bash
# Current keys are listed in JWKS
curl https://creddy.example.com/.well-known/jwks.json

# Admin can rotate keys
creddy admin keys rotate
```

Old keys remain valid for a grace period to allow token validation.

## Integrations

### AWS (OIDC Federation)

1. Create an OIDC provider in AWS IAM pointing to your Creddy server
2. Create a role with a trust policy for the OIDC provider
3. Agents can use `AssumeRoleWithWebIdentity` with their ID token

### GitHub Actions

Creddy-issued tokens can be used with services that support OIDC:

```yaml
- name: Get credentials
  run: |
    TOKEN=$(curl -s -X POST $CREDDY_URL/oauth/token ...)
    echo "ACCESS_TOKEN=$TOKEN" >> $GITHUB_ENV
```

## Debugging

### Validate a Token

```bash
# Decode without verification (for debugging)
echo "eyJ..." | cut -d. -f2 | base64 -d | jq

# Verify with JWKS
curl https://creddy.example.com/.well-known/jwks.json
```

### Check Discovery

```bash
curl https://creddy.example.com/.well-known/openid-configuration | jq
```

## Security Notes

1. **Token Lifetime**: Access tokens expire after 1 hour by default
2. **HTTPS Required**: Always use HTTPS in production
3. **Key Storage**: Client secrets should be stored securely (env vars, secrets manager)
4. **Scope Principle**: Request only the scopes you need
