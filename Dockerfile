FROM golang:1.25-alpine AS builder

RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

WORKDIR /src
COPY . .

RUN xcaddy build \
    --with github.com/realityone/caddy-shadowtls=. \
    --with github.com/caddy-dns/cloudflare@latest \
    --output /usr/bin/caddy

FROM alpine:latest

COPY --from=builder /usr/bin/caddy /usr/bin/caddy

ENTRYPOINT ["caddy"]
CMD ["run", "--config", "/etc/caddy/Caddyfile"]
