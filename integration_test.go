package shadowtls

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"

	shadowtls "github.com/sagernet/sing-shadowtls"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	_ "github.com/caddyserver/caddy/v2/modules/standard"
)

type testLogger struct {
	t *testing.T
}

func (l *testLogger) Trace(args ...any)                             { l.t.Log(args...) }
func (l *testLogger) Debug(args ...any)                             { l.t.Log(args...) }
func (l *testLogger) Info(args ...any)                              { l.t.Log(args...) }
func (l *testLogger) Warn(args ...any)                              { l.t.Log(args...) }
func (l *testLogger) Error(args ...any)                             { l.t.Log(args...) }
func (l *testLogger) Fatal(args ...any)                             { l.t.Fatal(args...) }
func (l *testLogger) Panic(args ...any)                             { l.t.Fatal(args...) }
func (l *testLogger) TraceContext(ctx context.Context, args ...any) { l.t.Log(args...) }
func (l *testLogger) DebugContext(ctx context.Context, args ...any) { l.t.Log(args...) }
func (l *testLogger) InfoContext(ctx context.Context, args ...any)  { l.t.Log(args...) }
func (l *testLogger) WarnContext(ctx context.Context, args ...any)  { l.t.Log(args...) }
func (l *testLogger) ErrorContext(ctx context.Context, args ...any) { l.t.Log(args...) }
func (l *testLogger) FatalContext(ctx context.Context, args ...any) { l.t.Fatal(args...) }
func (l *testLogger) PanicContext(ctx context.Context, args ...any) { l.t.Fatal(args...) }

// TestIntegrationShadowTLSV3HTTP tests the full ShadowTLS v3 auth and proxy
// routine over plain HTTP (no TLS on top of ShadowTLS).
func TestIntegrationShadowTLSV3HTTP(t *testing.T) {
	const (
		password        = "test-password"
		handshakeServer = "www.bytedance.com"
		handshakeAddr   = handshakeServer + ":443"
	)

	tester := caddytest.NewTester(t)
	tester.InitServer(fmt.Sprintf(`
	{
		skip_install_trust
		admin localhost:2999
		http_port 9080
		https_port 9443
		grace_period 1ns

		shadowtls {
			version 3
			user test-user %s
		}

		servers :9080 {
			listener_wrappers {
				shadowtls {
					handshake_server %s
				}
			}
			protocols h1
		}
	}
	http://:9080 {
		respond "hello shadowtls"
	}
	`, password, handshakeAddr), "caddyfile")

	logger := &testLogger{t: t}

	client, err := shadowtls.NewClient(shadowtls.ClientConfig{
		Version:  3,
		Password: password,
		Server:   M.ParseSocksaddr("127.0.0.1:9080"),
		Dialer:   N.SystemDialer,
		TLSHandshake: shadowtls.DefaultTLSHandshakeFunc(password, &tls.Config{
			ServerName: handshakeServer,
		}),
		Logger: logger,
	})
	if err != nil {
		t.Fatalf("create shadowtls client: %v", err)
	}

	conn, err := client.DialContext(context.Background())
	if err != nil {
		t.Fatalf("shadowtls dial: %v", err)
	}
	defer conn.Close()

	t.Log("shadowtls handshake succeeded, sending HTTP request")

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return conn, nil
			},
		},
	}

	resp, err := httpClient.Get("http://127.0.0.1:9080/")
	if err != nil {
		t.Fatalf("http get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	if string(body) != "hello shadowtls" {
		t.Fatalf("unexpected body: %q, want %q", string(body), "hello shadowtls")
	}

	t.Logf("got response: %q", string(body))
}

// TestIntegrationShadowTLSV3HTTPS tests the full ShadowTLS v3 auth and proxy
// routine with Caddy TLS on top (shadowtls -> tls -> http handler).
func TestIntegrationShadowTLSV3HTTPS(t *testing.T) {
	const (
		password        = "test-password"
		handshakeServer = "www.bytedance.com"
		handshakeAddr   = handshakeServer + ":443"
	)

	tester := caddytest.NewTester(t)
	tester.InitServer(fmt.Sprintf(`
	{
		skip_install_trust
		admin localhost:2999
		http_port 9080
		https_port 9443
		grace_period 1ns
		local_certs

		shadowtls {
			version 3
			user test-user %s
		}

		servers :9443 {
			listener_wrappers {
				shadowtls {
					handshake_server %s
				}
				tls
			}
		}
	}
	localhost:9443 {
		tls internal
		respond "hello shadowtls"
	}
	`, password, handshakeAddr), "caddyfile")

	logger := &testLogger{t: t}

	client, err := shadowtls.NewClient(shadowtls.ClientConfig{
		Version:  3,
		Password: password,
		Server:   M.ParseSocksaddr("127.0.0.1:9443"),
		Dialer:   N.SystemDialer,
		TLSHandshake: shadowtls.DefaultTLSHandshakeFunc(password, &tls.Config{
			ServerName: handshakeServer,
		}),
		Logger: logger,
	})
	if err != nil {
		t.Fatalf("create shadowtls client: %v", err)
	}

	conn, err := client.DialContext(context.Background())
	if err != nil {
		t.Fatalf("shadowtls dial: %v", err)
	}
	defer conn.Close()

	t.Log("shadowtls handshake succeeded, performing TLS handshake with Caddy")

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true,
	})
	if err := tlsConn.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("tls handshake: %v", err)
	}
	defer tlsConn.Close()

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return tlsConn, nil
			},
		},
	}

	resp, err := httpClient.Get("https://localhost:9443/")
	if err != nil {
		t.Fatalf("http get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	if string(body) != "hello shadowtls" {
		t.Fatalf("unexpected body: %q, want %q", string(body), "hello shadowtls")
	}

	t.Logf("got response: %q", string(body))
}
