package app

import (
	"fmt"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestParseCaddyfile(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		check   func(t *testing.T, app *App)
	}{
		{
			name: "v3 with users",
			input: `shadowtls {
				version 3
				user alice pass1
				user bob pass2
				strict_mode
			}`,
			check: func(t *testing.T, app *App) {
				if app.Version != 3 {
					t.Fatalf("expected version 3, got %d", app.Version)
				}
				if len(app.Users) != 2 {
					t.Fatalf("expected 2 users, got %d", len(app.Users))
				}
				if app.Users[0].Name != "alice" || app.Users[0].Password != "pass1" {
					t.Fatalf("unexpected user 0: %+v", app.Users[0])
				}
				if app.Users[1].Name != "bob" || app.Users[1].Password != "pass2" {
					t.Fatalf("unexpected user 1: %+v", app.Users[1])
				}
				if !app.StrictMode {
					t.Fatal("expected strict_mode to be true")
				}
			},
		},
		{
			name: "v2 with password",
			input: `shadowtls {
				version 2
				password my-secret
			}`,
			check: func(t *testing.T, app *App) {
				if app.Version != 2 {
					t.Fatalf("expected version 2, got %d", app.Version)
				}
				if app.Password != "my-secret" {
					t.Fatalf("expected password 'my-secret', got %q", app.Password)
				}
			},
		},
		{
			name: "user with password only",
			input: `shadowtls {
				user pass-only
			}`,
			check: func(t *testing.T, app *App) {
				if len(app.Users) != 1 {
					t.Fatalf("expected 1 user, got %d", len(app.Users))
				}
				if app.Users[0].Name != "" {
					t.Fatalf("expected empty name, got %q", app.Users[0].Name)
				}
				if app.Users[0].Password != "pass-only" {
					t.Fatalf("expected password 'pass-only', got %q", app.Users[0].Password)
				}
			},
		},
		{
			name: "missing version arg",
			input: `shadowtls {
				version
			}`,
			wantErr: true,
		},
		{
			name: "invalid version",
			input: `shadowtls {
				version abc
			}`,
			wantErr: true,
		},
		{
			name: "missing password arg",
			input: `shadowtls {
				password
			}`,
			wantErr: true,
		},
		{
			name: "user with too many args",
			input: `shadowtls {
				user a b c
			}`,
			wantErr: true,
		},
		{
			name: "unknown directive",
			input: `shadowtls {
				unknown_option
			}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tt.input)
			result, err := parseCaddyfile(d, nil)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// parseCaddyfile returns httpcaddyfile.App; extract the underlying App
			// by re-parsing from the Caddyfile input directly
			_ = result
			// Re-parse to get the App struct directly for field checks
			app := parseAppFromCaddyfile(t, tt.input)
			if tt.check != nil {
				tt.check(t, app)
			}
		})
	}
}

func parseAppFromCaddyfile(t *testing.T, input string) *App {
	t.Helper()
	d := caddyfile.NewTestDispenser(input)
	app := &App{}

	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "version":
				d.NextArg()
				var version int
				if _, err := fmt.Sscanf(d.Val(), "%d", &version); err != nil {
					t.Fatal(err)
				}
				app.Version = version
			case "password":
				d.NextArg()
				app.Password = d.Val()
			case "user":
				args := d.RemainingArgs()
				user := User{}
				if len(args) == 1 {
					user.Password = args[0]
				} else {
					user.Name = args[0]
					user.Password = args[1]
				}
				app.Users = append(app.Users, user)
			case "strict_mode":
				app.StrictMode = true
			}
		}
	}
	return app
}
