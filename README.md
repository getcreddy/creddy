# Creddy

Ephemeral credentials for AI agents.

## The Problem

Your AI agents need credentials to access services like GitHub, AWS, and Doppler. But:
- Sharing your personal tokens is a security risk
- Manually provisioning accounts for short-lived agents is tedious
- There's no audit trail of what each agent accessed

## The Solution

Creddy is a central identity service that:
1. Holds master credentials (GitHub App keys, AWS IAM roles, etc.)
2. Issues scoped, time-limited tokens to authenticated agents
3. Auto-revokes credentials when they expire
4. Provides audit logs of all credential usage

Agents never see your master credentials. They authenticate to Creddy, request what they need, and get short-lived tokens.

## Quick Start

### Server Setup

```bash
# Start the server (bind to tailnet IP for private access)
creddy server --listen 100.x.x.x:8400

# Add a GitHub App backend
creddy backend add github --app-id 123456 --private-key ./app.pem

# Create an agent identity
creddy agent create my-bot --can github:read,write
# Returns: ckr_abc123...
```

### Agent Usage

```bash
# Set credentials (on the agent machine)
export CREDDY_URL=http://creddy-server:8400
export CREDDY_TOKEN=ckr_abc123

# Request a GitHub token (10 minute TTL)
creddy get github --ttl 10m
# Returns: ghs_xxxxx

# List active credentials
creddy list

# Revoke a credential early
creddy revoke <id>
```

## Development

```bash
# Enter dev environment
nix develop

# Build
go build -o creddy .

# Run
./creddy --help
```

## Architecture

```
┌─────────────────┐
│  creddy server  │  ← holds master creds
│  (creddy-01)    │  ← listens on tailnet only
└────────┬────────┘
         │ tailnet
    ┌────┴────┬────────┬────────┐
    │         │        │        │
┌───┴───┐ ┌───┴───┐ ┌──┴──┐ ┌───┴───┐
│agent-1│ │agent-2│ │agent│ │ ...   │
└───────┘ └───────┘ └─────┘ └───────┘
```

## Backends

### GitHub (v0.1)
Uses GitHub App installation tokens. Requires:
- GitHub App ID
- Private key (.pem file)

### AWS (planned)
Uses STS AssumeRole. Will require:
- IAM role ARN
- Trust policy for Creddy

### Doppler (planned)
Service tokens via Doppler API.

## License

MIT
