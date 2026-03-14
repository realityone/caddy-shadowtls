package shadowtls

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddytest"

	_ "github.com/caddyserver/caddy/v2/modules/standard"
)

func TestCaddyfileAdaptV3(t *testing.T) {
	caddytest.AssertAdapt(t, `
	{
		skip_install_trust
		admin localhost:2999
		http_port 9080
		https_port 9443

		shadowtls {
			version 3
			user alice secret1
			user bob secret2
			strict_mode
		}

		servers :9443 {
			listener_wrappers {
				shadowtls {
					handshake_server www.example.com:443
					handshake_for_server_name custom.example.com alt.example.com:443
				}
			}
		}
	}
	:9443 {
		respond "hello"
	}
	`, "caddyfile", `{
	"admin": {
		"listen": "localhost:2999"
	},
	"apps": {
		"http": {
			"http_port": 9080,
			"https_port": 9443,
			"servers": {
				"srv0": {
					"listen": [
						":9443"
					],
					"listener_wrappers": [
						{
							"handshake_for_server_name": {
								"custom.example.com": "alt.example.com:443"
							},
							"handshake_server": "www.example.com:443",
							"wrapper": "shadowtls"
						}
					],
					"routes": [
						{
							"handle": [
								{
									"body": "hello",
									"handler": "static_response"
								}
							]
						}
					]
				}
			}
		},
		"pki": {
			"certificate_authorities": {
				"local": {
					"install_trust": false
				}
			}
		},
		"shadowtls": {
			"version": 3,
			"users": [
				{
					"name": "alice",
					"password": "secret1"
				},
				{
					"name": "bob",
					"password": "secret2"
				}
			],
			"strict_mode": true
		}
	}
}`)
}

func TestCaddyfileAdaptV2(t *testing.T) {
	caddytest.AssertAdapt(t, `
	{
		skip_install_trust
		admin localhost:2999
		http_port 9080
		https_port 9443

		shadowtls {
			version 2
			password my-password
		}

		servers :9443 {
			listener_wrappers {
				shadowtls {
					handshake_server www.example.com:443
				}
			}
		}
	}
	:9443 {
		respond "hello"
	}
	`, "caddyfile", `{
	"admin": {
		"listen": "localhost:2999"
	},
	"apps": {
		"http": {
			"http_port": 9080,
			"https_port": 9443,
			"servers": {
				"srv0": {
					"listen": [
						":9443"
					],
					"listener_wrappers": [
						{
							"handshake_server": "www.example.com:443",
							"wrapper": "shadowtls"
						}
					],
					"routes": [
						{
							"handle": [
								{
									"body": "hello",
									"handler": "static_response"
								}
							]
						}
					]
				}
			}
		},
		"pki": {
			"certificate_authorities": {
				"local": {
					"install_trust": false
				}
			}
		},
		"shadowtls": {
			"version": 2,
			"password": "my-password"
		}
	}
}`)
}

func TestLoadConfigV3NoUsers(t *testing.T) {
	config := json.RawMessage(`{
		"apps": {
			"shadowtls": {
				"version": 3
			}
		}
	}`)

	err := caddy.Load(config, true)
	if err == nil {
		t.Fatal("expected error for v3 with no users")
	}
	if got := err.Error(); !strings.Contains(got, "shadowtls v3 requires at least one user") {
		t.Fatalf("unexpected error: %s", got)
	}
}

func TestLoadConfigV2NoPassword(t *testing.T) {
	config := json.RawMessage(`{
		"apps": {
			"shadowtls": {
				"version": 2
			}
		}
	}`)

	err := caddy.Load(config, true)
	if err == nil {
		t.Fatal("expected error for v2 with no password")
	}
	if got := err.Error(); !strings.Contains(got, "shadowtls v2 requires a password") {
		t.Fatalf("unexpected error: %s", got)
	}
}

func TestLoadConfigInvalidVersion(t *testing.T) {
	config := json.RawMessage(`{
		"apps": {
			"shadowtls": {
				"version": 5
			}
		}
	}`)

	err := caddy.Load(config, true)
	if err == nil {
		t.Fatal("expected error for invalid version")
	}
	if got := err.Error(); !strings.Contains(got, "unknown shadowtls version") {
		t.Fatalf("unexpected error: %s", got)
	}
}

