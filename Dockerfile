# syntax=docker/dockerfile:1

FROM golang:latest AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o portal ./cmd/portal

FROM gcr.io/distroless/base-debian12

WORKDIR /portal
COPY --from=builder /app/portal /portal/portal
COPY --from=builder /app/web /portal/web
COPY --from=builder /app/content /portal/content
COPY --from=builder /app/internal/storage/migrations /portal/migrations

ENV PORTAL_TEMPLATES_DIR=/portal/web/templates \
    PORTAL_STATIC_DIR=/portal/web/static \
    PORTAL_CONTENT_DIR=/portal/content

EXPOSE 8080

ENTRYPOINT ["/portal/portal"]
