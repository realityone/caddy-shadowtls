package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	_ "github.com/caddyserver/caddy/v2/modules/standard"

	_ "github.com/realityone/caddy-shadowtls"
)

func main() {
	caddycmd.Main()
}
