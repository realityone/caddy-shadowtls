# caddy-shadowtls

A [Caddy](https://caddyserver.com/) module that wraps [ShadowTLS](https://github.com/ihciah/shadow-tls) as a listener wrapper. It performs the ShadowTLS handshake on incoming connections before passing unwrapped connections to Caddy's handler chain.

## Build

Build a custom Caddy binary with ShadowTLS support:

```bash
go build -o caddy ./cmd/caddy
```

## Caddyfile Example

### ShadowTLS + HTTPS

ShadowTLS unwraps the connection first, then Caddy terminates TLS as usual:

```caddyfile
{
    shadowtls {
        version 3
        user alice p@ssw0rd
        user bob s3cret
    }

    servers :443 {
        listener_wrappers {
            shadowtls {
                handshake_server www.example.com:443
            }
            tls
        }
    }
}

example.com {
    tls you@example.com
    respond "Hello from behind ShadowTLS"
}
```

### ShadowTLS + HTTP (no TLS)

Useful for testing or when TLS termination happens elsewhere:

```caddyfile
{
    http_port 8080

    shadowtls {
        version 3
        user alice p@ssw0rd
    }

    servers :8080 {
        listener_wrappers {
            shadowtls {
                handshake_server www.example.com:443
            }
        }
        protocols h1
    }
}

http://:8080 {
    respond "Hello from behind ShadowTLS"
}
```

### Global Options

| Directive     | Description                                      |
|---------------|--------------------------------------------------|
| `version`     | ShadowTLS protocol version (e.g. `3`)            |
| `password`    | Shared password (single-user mode)               |
| `user`        | Named user with password (`user <name> <pass>`)  |
| `strict_mode` | Enable strict mode                               |

### Listener Wrapper Options

| Directive                    | Description                                                        |
|------------------------------|--------------------------------------------------------------------|
| `handshake_server`           | Address of the TLS server used for the handshake (e.g. `www.example.com:443`) |
| `handshake_for_server_name`  | Additional SNI names and optional alternate handshake addresses     |
