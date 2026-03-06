# Agent Identity Protocol (AIP) v1

**Status:** Draft  
**Version:** 1.0.0-draft  
**Date:** 2026-03-06

## Abstract

The Agent Identity Protocol (AIP) defines a standard way for AI agents to establish identity, authenticate to services, and obtain scoped credentials. It builds on OpenID Connect (OIDC) to provide a familiar authentication model while adding agent-specific extensions for ephemeral credential management.

## 1. Introduction

AI agents need to interact with external services (GitHub, AWS, databases, APIs) but face unique challenges:

1. **Identity**: How does a service know which agent is making a request?
2. **Authorization**: What is the agent allowed to do?
3. **Credential Lifecycle**: How are credentials issued, scoped, and revoked?
4. **Audit**: How do we track what each agent accessed?

AIP addresses these challenges by:

- Using OIDC for agent authentication and identity tokens
- Defining agent-specific claims for identity and scoping
- Providing a credential exchange endpoint for ephemeral tokens
- Supporting multiple authentication methods (OIDC and vend tokens)

## 2. Terminology

- **Agent**: An autonomous AI system that acts on behalf of a user or organization
- **Creddy Server**: The AIP-compliant identity provider
- **Client Credentials**: The `client_id` and `client_secret` used for OIDC authentication
- **Access Token**: A JWT granting access to Creddy API endpoints
- **ID Token**: A JWT containing agent identity claims
- **Backend**: An external service (GitHub, AWS, etc.) that Creddy can issue credentials for
- **Credential**: A short-lived token for a specific backend

## 3. OIDC Compliance

AIP is built on OIDC Core 1.0 with the following profile:

### 3.1 Discovery

The server MUST provide an OIDC discovery document at:

```
GET /.well-known/openid-configuration
```

Required fields:
- `issuer`: The Creddy server URL
- `token_endpoint`: URL for token requests
- `jwks_uri`: URL for public keys
- `response_types_supported`: `["token"]`
- `subject_types_supported`: `["public"]`
- `id_token_signing_alg_values_supported`: `["RS256"]`
- `grant_types_supported`: `["client_credentials"]`

Extension fields:
- `credential_exchange_endpoint`: URL for credential requests

### 3.2 JSON Web Key Set (JWKS)

The server MUST provide public keys at:

```
GET /.well-known/jwks.json
```

Keys MUST include:
- `kty`: Key type (RSA)
- `use`: `sig`
- `kid`: Key identifier
- `alg`: `RS256`
- `n`, `e`: RSA public key components

### 3.3 Token Endpoint

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_id=agent_abc123
&client_secret=cks_xxx
&scope=openid github
```

Response:
```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "id_token": "eyJ...",
  "scope": "openid github"
}
```

## 4. Agent Identity Claims

### 4.1 Standard OIDC Claims

| Claim | Description |
|-------|-------------|
| `iss` | Issuer URL |
| `sub` | Agent ID (unique identifier) |
| `aud` | Intended audience |
| `exp` | Expiration timestamp |
| `iat` | Issued at timestamp |
| `auth_time` | Authentication timestamp |

### 4.2 Agent Extension Claims

| Claim | Type | Description |
|-------|------|-------------|
| `agent_id` | string | Unique agent identifier |
| `agent_name` | string | Human-readable agent name |
| `scopes` | string[] | Granted permission scopes |
| `client_id` | string | OIDC client identifier |
| `task_id` | string | Current task identifier (optional) |
| `task_description` | string | Brief task description (optional) |
| `parent_agent_id` | string | Parent agent if spawned (optional) |
| `ip_restriction` | string | IP/CIDR restriction (optional) |

### 4.3 Example ID Token

```json
{
  "iss": "https://creddy.example.com",
  "sub": "agent-123",
  "aud": ["https://creddy.example.com"],
  "exp": 1709740800,
  "iat": 1709737200,
  "auth_time": 1709737200,
  "agent_id": "agent-123",
  "agent_name": "my-coding-agent",
  "scopes": ["github:read", "github:write"],
  "client_id": "agent_abc123"
}
```

## 5. Credential Exchange

### 5.1 Request

```
POST /v1/credentials/{backend}
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "ttl": "10m",
  "scopes": ["repo:read"]
}
```

Or with query parameters:
```
POST /v1/credentials/github?ttl=10m&repo=owner/repo
Authorization: Bearer <access_token>
```

### 5.2 Response

```json
{
  "token": "ghs_xxxx",
  "expires_at": "2026-03-06T13:00:00Z",
  "ttl": "10m0s"
}
```

### 5.3 Scope Format

Scopes follow the pattern: `{backend}:{resource}:{permission}`

Examples:
- `github:repo:read` - Read access to repositories
- `github:owner/repo:write` - Write access to specific repo
- `aws:s3:read` - Read access to S3
- `doppler:project/config:read` - Read secrets from Doppler

Wildcards are supported:
- `github:*` - All GitHub permissions
- `*` - All permissions (use with caution)

## 6. Authentication Methods

AIP supports two authentication methods for backward compatibility:

### 6.1 OIDC Native (Recommended)

1. Agent obtains `client_id` and `client_secret` during enrollment
2. Agent requests tokens via `/oauth/token` endpoint
3. Agent uses access token for API requests

```bash
# Get tokens
TOKEN=$(curl -s -X POST https://creddy.example.com/oauth/token \
  -d "grant_type=client_credentials" \
  -d "client_id=agent_abc123" \
  -d "client_secret=cks_xxx" \
  | jq -r .access_token)

# Use access token
curl https://creddy.example.com/v1/credentials/github \
  -H "Authorization: Bearer $TOKEN"
```

### 6.2 Vend Token

Agents may use vend tokens (`ckr_`) directly, bypassing the OAuth exchange:

```bash
curl https://creddy.example.com/v1/credentials/github \
  -H "Authorization: Bearer ckr_xxx"
```

Vend tokens are detected by their prefix and validated against a stored hash.

## 7. Agent Enrollment

### 7.1 CLI Enrollment

```bash
creddy enroll https://creddy.example.com --name my-agent --scopes github
```

### 7.2 Enrollment Response

```json
{
  "id": "agent-uuid",
  "name": "my-agent",
  "token": "ckr_xxx",
  "oidc": {
    "client_id": "agent_abc123",
    "client_secret": "cks_xxx"
  },
  "scopes": ["github"],
  "created_at": "2026-03-06T12:00:00Z"
}
```

Both credentials are shown only once. Store them securely.

## 8. Security Considerations

### 8.1 Token Lifetime

- Access tokens SHOULD have a short lifetime (1 hour default)
- Backend credentials SHOULD be even shorter (10 minutes default)
- Refresh is done by requesting new tokens from `/oauth/token`

### 8.2 Scope Validation

- Requested scopes MUST be validated against agent's allowed scopes
- Backend credentials MUST be scoped to the minimum required permissions

### 8.3 Key Rotation

- Signing keys SHOULD be rotated periodically
- Old keys remain in JWKS for validation during grace period
- Clients SHOULD fetch JWKS periodically or use caching with max-age

### 8.4 Audit Logging

All credential operations MUST be logged:
- Token issuance
- Credential requests
- Credential revocation
- Scope changes

## 9. Error Responses

Standard OAuth 2.0 error format:

```json
{
  "error": "invalid_client",
  "error_description": "Client authentication failed"
}
```

Common errors:
- `invalid_client`: Invalid client credentials
- `invalid_grant`: Invalid or expired grant
- `invalid_scope`: Requested scope not allowed
- `unauthorized_client`: Client not authorized for grant type

## 10. Implementation Notes

### 10.1 Credential Format

| Credential Type | Format | Example |
|-----------------|--------|---------|
| Vend Token | `ckr_` + 48 hex | `ckr_abc123...` |
| Client ID | `agent_` + 12 hex | `agent_abc123` |
| Client Secret | `cks_` + 32 hex | `cks_xyz789...` |

### 10.2 JWT Validation

1. Extract `kid` from JWT header
2. Fetch matching key from JWKS
3. Verify RS256 signature
4. Validate `iss`, `aud`, `exp` claims
5. Extract agent identity from claims

## Appendix A: Full Example Flow

```bash
# 1. Enroll agent (one-time)
creddy enroll https://creddy.example.com \
  --name "my-agent" \
  --scopes "github:owner/repo:write"

# Save credentials
# client_id: agent_abc123
# client_secret: cks_xyz789...

# 2. Get access token
ACCESS_TOKEN=$(curl -s -X POST \
  https://creddy.example.com/oauth/token \
  -d "grant_type=client_credentials" \
  -d "client_id=agent_abc123" \
  -d "client_secret=cks_xyz789" \
  -d "scope=openid github" \
  | jq -r .access_token)

# 3. Request ephemeral GitHub token
GITHUB_TOKEN=$(curl -s \
  https://creddy.example.com/v1/credentials/github?ttl=10m \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  | jq -r .token)

# 4. Use GitHub token
gh api repos/owner/repo --with-token "$GITHUB_TOKEN"
```

## Appendix B: Related Specifications

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OAuth 2.0 Client Credentials Grant](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4)
- [JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- [JSON Web Key (JWK)](https://datatracker.ietf.org/doc/html/rfc7517)
