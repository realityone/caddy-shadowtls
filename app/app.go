package app

import (
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"

	shadowtls "github.com/sagernet/sing-shadowtls"
)

func init() {
	caddy.RegisterModule(App{})
}

const CaddyAppID = "shadowtls"

type User struct {
	Name     string `json:"name,omitempty"`
	Password string `json:"password"`
}

type App struct {
	Version    int    `json:"version,omitempty"`
	Password   string `json:"password,omitempty"`
	Users      []User `json:"users,omitempty"`
	StrictMode bool   `json:"strict_mode,omitempty"`

	lg *zap.Logger
}

func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  CaddyAppID,
		New: func() caddy.Module { return new(App) },
	}
}

func (a *App) Provision(ctx caddy.Context) error {
	a.lg = ctx.Logger(a)

	if a.Version == 0 {
		a.Version = 3
	}
	switch a.Version {
	case 1, 2, 3:
	default:
		return fmt.Errorf("unknown shadowtls version: %d", a.Version)
	}
	if a.Version == 3 && len(a.Users) == 0 {
		return fmt.Errorf("shadowtls v3 requires at least one user")
	}
	if a.Version == 2 && a.Password == "" {
		return fmt.Errorf("shadowtls v2 requires a password")
	}

	return nil
}

func (a *App) Start() error {
	return nil
}

func (a *App) Stop() error {
	return nil
}

func (a *App) GetUsers() []shadowtls.User {
	users := make([]shadowtls.User, len(a.Users))
	for i, u := range a.Users {
		users[i] = shadowtls.User{
			Name:     u.Name,
			Password: u.Password,
		}
	}
	return users
}

var (
	_ caddy.App         = (*App)(nil)
	_ caddy.Provisioner = (*App)(nil)
)
