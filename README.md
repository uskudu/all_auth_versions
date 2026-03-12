# All Auth Versions

A comprehensive collection of authentication implementations across major versions and providers, enabling developers to test, compare, and migrate auth flows seamlessly. Supports OAuth2, OpenID Connect, JWT, and more.

## Table of Contents
- [Features](#features)
- [Quick Start](#quick-start)
- [Supported Auth](#supported-auth)
- [Usage](#usage)
- [Structure](#structure)
- [Contributing](#contributing)

## Features
- Side-by-side auth flows for legacy (OAuth1/OAuth2 v1) vs modern (PKCE, OIDC).
- Standardized API surface across providers (Google, GitHub, Auth0, Firebase).
- Dockerized examples for each version/provider combo.
- JWT validation, token refresh, and session management utilities.
- Zero-dependency core with optional provider plugins.

## Quick Start
```bash
git clone https://github.com/uskudu/all_auth_versions.git
cd all_auth_versions

# Run all providers with Docker Compose
docker-compose up

# Or install and run locally
go mod tidy
go run ./cmd/demo --providers=all
```
Access demos at `http://localhost:8080/{provider}/{version}` (e.g., `/google/oauth2`).

## Supported Auth
| Provider | Versions | Status |
|----------|----------|--------|
| Google | OAuth2, OIDC, PKCE | ✅ |
| GitHub | OAuth2 v1-v4 | ✅ |
| Auth0 | Legacy JWT, Universal Login | 🛠️ |
| Firebase | v8 Admin SDK, v10+ | ✅ |
| Generic | JWT RS256, HS512 | ✅ |

## Usage
```go
import (
    "github.com/uskudu/all_auth_versions/oauth2"
    "github.com/uskudu/all_auth_versions/jwt"
)

// OAuth2 flow (interchangeable across providers)
client := oauth2.NewGoogleClient(ctx, oauth2.WithPKCE())
url := client.AuthURL(state)
token, err := client.Exchange(code) // Handles all versions

// JWT validation (multi-algo)
validator := jwt.NewValidator(jwt.RS256|jwt.HS512)
claims, err := validator.Validate(token)
```

**API Endpoints (when running demo):**
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/{provider}/login` | GET | Redirect to provider auth URL |
| `/auth/{provider}/callback` | GET | Exchange code for tokens |
| `/auth/validate` | POST | Validate JWT across versions |
| `/tokens/refresh` | POST | Refresh token (version-aware) |

## Structure
```
all_auth_versions/
├── cmd/
│   └── demo/           # HTTP demo server
├── internal/
│   ├── providers/      # Provider-specific impls
│   │   ├── google/
│   │   ├── github/
│   │   └── generic/
│   ├── flows/          # Auth flows (OAuth1/2, OIDC)
│   └── jwt/            # Token validation
├── examples/           # Dockerized full flows
├── go.mod
└── README.md
```

## Contributing
1. Fork and create a feature branch: `git checkout -b feature/providerX`
2. Add your provider/flow in `internal/providers/`
3. Update `supported-auth` table above
4. Add tests: `go test ./...`
5. PR with changelog entry

**Guidelines:**
- Keep API surface identical across providers
- Support at least OAuth2 + PKCE
- Include Docker example
- No external deps in core
