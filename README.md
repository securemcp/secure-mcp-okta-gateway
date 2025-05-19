# Secure MCP Okta Gateway

## Overview

Secure MCP Okta Gateway is a gateway server that provides OAuth 2.0 Authorization Server and Resource Server functionalities, acting as a bridge between Model Context Protocol (MCP) clients and Okta authentication. It supports dynamic client registration, authorization, token issuance, and proxying requests to backend services, all while enforcing secure authentication and authorization flows.

## Features

- OAuth 2.0 Authorization Server endpoints (dynamic client registration, authorization, token, etc.)
- Okta integration for user authentication
- Secure token issuance and validation
- Reverse proxy for protected backend services
- Health check endpoint
- Configurable via YAML and environment variables
- Redis-based session and token storage
- Structured logging

## Requirements

- Go 1.24 or later
- Redis server

## Installation

```sh
git clone https://github.com/securemcp/securemcp-okta-gateway.git
cd securemcp-okta-gateway
go build -o securemcp-okta-gateway
```

## Configuration

Edit `config.yaml` to define proxy routes:

```yaml
proxies:
  - pattern: "/mcp/dice/"
    target_url: "http://localhost:3000"
  - pattern: "/mcp/uuid/"
    target_url: "http://localhost:4000"
```

Set environment variables as needed (see `.env.sample` for examples):

- `KVS_ADDR`: Redis address (e.g., `localhost:6379`)
- `KVS_PASSWORD`: Redis password
- `PORT`: Port to run the server (default: `8080`)
- `OKTA_URL`, `OKTA_CLIENT_ID`, `OKTA_CLIENT_SECRET`, `OKTA_REDIRECT_URI`: Okta OAuth settings

## Usage

Start the server:

```sh
./securemcp-okta-gateway
```

## Endpoints

- `GET  /healthz` — Health check
- `POST /auth/register` — Dynamic client registration
- `GET  /auth/authorize` — OAuth authorization endpoint
- `GET  /auth/callback` — OAuth callback endpoint
- `POST /auth/token` — Token issuance endpoint
- `GET  /.well-known/oauth-authorization-server` — Authorization server metadata
- `GET  /.well-known/oauth-protected-resource` — Resource server metadata
- Proxy endpoints as defined in `config.yaml` (e.g., `/mcp/dice/`, `/mcp/uuid/`)

## MCP Clients

Cursor MCP Clients

```json
{
  "mcpServers": {
    "dice": {
      "command": "npx",
      "args": ["-y", "mcp-remote@latest", "http://localhost:8080/mcp/dice/mcp"]
    },
    "uuid": {
      "command": "npx",
      "args": ["-y", "mcp-remote@latest", "http://localhost:8080/mcp/uuid/mcp"]
    },
  }
}
```

## License

MIT License

## References

- [MCP Authorization Specification](https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization)
- [MCP GitHub Specification](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/draft/basic/authorization.mdx)
