package app

import (
	"fmt"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

func init() {
	httpcaddyfile.RegisterGlobalOption("shadowtls", parseCaddyfile)
}

/*
	shadowtls {
		version 3
		password my-password
		user name1 pass1
		user name2 pass2
		strict_mode
	}
*/
func parseCaddyfile(d *caddyfile.Dispenser, _ any) (any, error) {
	app := &App{}

	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "version":
				var version int
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				if _, err := fmt.Sscanf(d.Val(), "%d", &version); err != nil {
					return nil, d.Errf("invalid version: %s", d.Val())
				}
				app.Version = version
			case "password":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				app.Password = d.Val()
			case "user":
				args := d.RemainingArgs()
				if len(args) < 1 || len(args) > 2 {
					return nil, d.ArgErr()
				}
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
			default:
				return nil, d.ArgErr()
			}
		}
	}

	return httpcaddyfile.App{
		Name:  CaddyAppID,
		Value: caddyconfig.JSON(app, nil),
	}, nil
}
