# dystopian.earth portal

Skeleton Golang web portal for an online community / hacker collective. It includes:

- Markdown-driven public pages for easy content updates
- Registration flow with invite code and challenge response placeholders
- Admin moderation queues for registrations and invite code management
- Member dashboard with profile and payment placeholders
- SQLite (via modernc.org/sqlite) for storage and Redis-backed sessions
- Dockerized deployment with optional docker-compose stack

## Getting started

### Prerequisites

- Go 1.21+
- Redis (for sessions)
- SQLite is embedded via the Go driver, no external server needed

### Environment variables

| Variable | Default | Description |
| --- | --- | --- |
| `PORTAL_ADDR` | `:8080` | Listen address for the HTTP server |
| `PORTAL_DSN` | `file:portal.db?_pragma=foreign_keys(ON)` | SQLite DSN |
| `PORTAL_REDIS_ADDR` | `127.0.0.1:6379` | Redis address for sessions |
| `PORTAL_REDIS_PASSWORD` | `` | Redis password, if any |
| `PORTAL_SESSION_TTL` | `720h` | Session lifetime |
| `PORTAL_INVITE_SECRET` | `change-me` | Secret used when verifying invite challenges |
| `PORTAL_CONTENT_DIR` | `content` | Markdown content root |
| `PORTAL_TEMPLATES_DIR` | `web/templates` | Templates directory |
| `PORTAL_STATIC_DIR` | `web/static` | Static assets directory |

### Run locally

```bash
go run ./cmd/portal
```

The server will run on `http://localhost:8080` by default. Redis must be available at `PORTAL_REDIS_ADDR`.

### Docker

Build and run via Docker:

```bash
docker build -t dystopian-earth .
docker run --rm -p 8080:8080 --env PORTAL_REDIS_ADDR=host.docker.internal:6379 dystopian-earth
```

### Docker Compose

A `docker-compose.yml` is provided to run the portal alongside Redis. The SQLite database persists within a named volume.

```bash
docker compose up --build
```

## Content management

Public pages are stored under `content/pages`. Add a new Markdown file and it will be available at `/pages/<filename>`.

## Next steps

This project is a skeleton. You still need to:

- Implement the registration workflow with invite code validation and admin approval
- Wire up authentication and password hashing
- Connect payment metadata to your billing provider (Stripe, Patreon, etc.)
- Harden security (rate limiting, CSRF protections, etc.)

## License

MIT
