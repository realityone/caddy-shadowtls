package shadowtls

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddytest"
	shadowtls "github.com/sagernet/sing-shadowtls"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Exercise the HTTP/1 connection handoff used by reverse_proxy WebSockets with
// both ShadowTLS and inner TLS. All servers and certificates are local fixtures.
func TestIntegrationShadowTLSV3HTTPSUpgrade(t *testing.T) {
	const password = "test-upgrade-password"
	decoy := httptest.NewUnstartedServer(nil)
	decoy.Config.ErrorLog = log.New(io.Discard, "", 0)
	decoy.StartTLS()
	defer decoy.Close()
	roots := x509.NewCertPool()
	roots.AddCert(decoy.Certificate())

	backendErrors := make(chan error, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			backendErrors <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, err = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")
		if err == nil {
			err = rw.Flush()
		}
		// Three masked WebSocket text frames, sent only after the upgrade.
		for i := 0; i < 3 && err == nil; i++ {
			frame := make([]byte, 10)
			if _, err = io.ReadFull(rw, frame); err != nil {
				break
			}
			if frame[0] != 0x81 || frame[1] != 0x84 {
				err = fmt.Errorf("unexpected WebSocket frame header: %x", frame[:2])
				break
			}
			for j := 0; j < 4; j++ {
				frame[6+j] ^= frame[2+j]
			}
			_, err = conn.Write(append([]byte{0x81, 4}, frame[6:]...))
		}
		backendErrors <- err
	}))
	defer backend.Close()

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
			protocols h1
		}
	}
	localhost:9443 {
		tls internal
		reverse_proxy %s
	}
	`, password, decoy.Listener.Addr(), strings.TrimPrefix(backend.URL, "http://")), "caddyfile")

	client, err := shadowtls.NewClient(shadowtls.ClientConfig{
		Version:  3,
		Password: password,
		Server:   M.ParseSocksaddr("127.0.0.1:9443"),
		Dialer:   N.SystemDialer,
		TLSHandshake: shadowtls.DefaultTLSHandshakeFunc(password, &tls.Config{
			ServerName: "example.com",
			RootCAs:    roots,
		}),
		Logger: logger.NOP(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true, // Caddy's local test CA is not installed.
	})
	defer tlsConn.Close()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	_, err = io.WriteString(tlsConn, "GET /ws HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(tlsConn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status: %d", resp.StatusCode)
	}
	for i := 0; i < 3; i++ {
		// Mask "ping" with the fixed test mask 01 02 03 04.
		if _, err := tlsConn.Write([]byte{0x81, 0x84, 1, 2, 3, 4, 'p' ^ 1, 'i' ^ 2, 'n' ^ 3, 'g' ^ 4}); err != nil {
			t.Fatal(err)
		}
		frame := make([]byte, 6)
		if _, err := io.ReadFull(reader, frame); err != nil {
			t.Fatalf("WebSocket reply %d after upgrade: %v", i+1, err)
		}
		if frame[0] != 0x81 || frame[1] != 4 || string(frame[2:]) != "ping" {
			t.Fatalf("unexpected WebSocket reply: %x", frame)
		}
	}
	if err := <-backendErrors; err != nil {
		t.Fatalf("WebSocket backend: %v", err)
	}
}
