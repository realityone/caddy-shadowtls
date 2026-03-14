package listener

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestUnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		check   func(t *testing.T, lw *ListenerWrapper)
	}{
		{
			name: "basic handshake_server",
			input: `shadowtls {
				handshake_server www.example.com:443
			}`,
			check: func(t *testing.T, lw *ListenerWrapper) {
				if lw.HandshakeServer != "www.example.com:443" {
					t.Fatalf("expected handshake_server 'www.example.com:443', got %q", lw.HandshakeServer)
				}
			},
		},
		{
			name: "with handshake_for_server_name",
			input: `shadowtls {
				handshake_server www.example.com:443
				handshake_for_server_name sni.example.com alt.example.com:443
				handshake_for_server_name other.com other-hs.com:443
			}`,
			check: func(t *testing.T, lw *ListenerWrapper) {
				if lw.HandshakeServer != "www.example.com:443" {
					t.Fatalf("expected handshake_server 'www.example.com:443', got %q", lw.HandshakeServer)
				}
				if len(lw.HandshakeForServerName) != 2 {
					t.Fatalf("expected 2 handshake_for_server_name entries, got %d", len(lw.HandshakeForServerName))
				}
				if lw.HandshakeForServerName["sni.example.com"] != "alt.example.com:443" {
					t.Fatalf("unexpected mapping for sni.example.com: %q", lw.HandshakeForServerName["sni.example.com"])
				}
				if lw.HandshakeForServerName["other.com"] != "other-hs.com:443" {
					t.Fatalf("unexpected mapping for other.com: %q", lw.HandshakeForServerName["other.com"])
				}
			},
		},
		{
			name:    "missing handshake_server arg",
			input:   `shadowtls {
				handshake_server
			}`,
			wantErr: true,
		},
		{
			name:    "handshake_for_server_name with one arg",
			input:   `shadowtls {
				handshake_for_server_name only-one
			}`,
			wantErr: true,
		},
		{
			name:    "handshake_for_server_name with three args",
			input:   `shadowtls {
				handshake_for_server_name a b c
			}`,
			wantErr: true,
		},
		{
			name:    "unknown directive",
			input:   `shadowtls {
				unknown_option value
			}`,
			wantErr: true,
		},
		{
			name:    "unexpected arg after directive name",
			input:   `shadowtls unexpected_arg {
			}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tt.input)
			lw := &ListenerWrapper{}
			err := lw.UnmarshalCaddyfile(d)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, lw)
			}
		})
	}
}
