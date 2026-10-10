package listener

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	shadowtls "github.com/sagernet/sing-shadowtls"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// HTTP/1 hijacking cancels its background read with an expired deadline, then
// clears that deadline before handing the connection to the upgraded protocol.
// This must not send a ShadowTLS alert or prevent subsequent reads and writes.
func TestShadowTLSReadDeadlineResumes(t *testing.T) {
	const password = "test-password"
	decoy := httptest.NewUnstartedServer(nil)
	decoy.Config.ErrorLog = log.New(io.Discard, "", 0)
	decoy.StartTLS()
	t.Cleanup(decoy.Close)
	roots := x509.NewCertPool()
	roots.AddCert(decoy.Certificate())

	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := NewListener(inner, shadowtls.ServiceConfig{
		Version: 3,
		Users:   []shadowtls.User{{Password: password}},
		Handshake: shadowtls.HandshakeConfig{
			Server: M.ParseSocksaddr(decoy.Listener.Addr().String()),
			Dialer: N.SystemDialer,
		},
		Logger: logger.NOP(),
	})
	if err != nil {
		inner.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	client, err := shadowtls.NewClient(shadowtls.ClientConfig{
		Version:  3,
		Password: password,
		Server:   M.ParseSocksaddr(ln.Addr().String()),
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// The first authenticated record completes the server's ShadowTLS handshake.
	if _, err := conn.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	first := make([]byte, len("first"))
	if _, err := io.ReadFull(server, first); err != nil {
		t.Fatal(err)
	}
	if string(first) != "first" {
		t.Fatalf("unexpected first record: %q", first)
	}
	if err := server.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read should time out, got %v", err)
	}
	if err := server.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("after timeout")); err != nil {
		t.Fatal(err)
	}
	request := make([]byte, len("after timeout"))
	if _, err := io.ReadFull(server, request); err != nil {
		t.Fatalf("server read after clearing deadline: %v", err)
	}
	if _, err := server.Write(request); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(request))
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatalf("client read after clearing server deadline: %v", err)
	}
	if string(response) != "after timeout" {
		t.Fatalf("unexpected response: %q", response)
	}
}
