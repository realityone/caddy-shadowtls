package listener

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"

	"github.com/realityone/caddy-shadowtls/app"
	shadowtls "github.com/sagernet/sing-shadowtls"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func init() {
	caddy.RegisterModule(ListenerWrapper{})
}

// ListenerWrapper wraps a net.Listener with ShadowTLS.
// It performs the ShadowTLS handshake on incoming connections and
// delivers unwrapped connections to Caddy's TLS layer.
type ListenerWrapper struct {
	// HandshakeServer is the TLS server to mimic during the handshake (e.g. "www.bytedance.com:443").
	HandshakeServer string `json:"handshake_server"`

	// HandshakeForServerName maps SNI values to alternative handshake servers.
	HandshakeForServerName map[string]string `json:"handshake_for_server_name,omitempty"`

	logger *zap.Logger
	app    *app.App
}

func (ListenerWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.shadowtls",
		New: func() caddy.Module { return new(ListenerWrapper) },
	}
}

func (m *ListenerWrapper) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	if _, err := ctx.AppIfConfigured(app.CaddyAppID); err != nil {
		return fmt.Errorf("shadowtls configure error: %w", err)
	}
	mod, err := ctx.App(app.CaddyAppID)
	if err != nil {
		return err
	}
	m.app = mod.(*app.App)

	if m.HandshakeServer == "" {
		return fmt.Errorf("handshake_server is required")
	}

	return nil
}

func (m *ListenerWrapper) WrapListener(l net.Listener) net.Listener {
	handshakeForServerName := make(map[string]shadowtls.HandshakeConfig, len(m.HandshakeForServerName))
	for sni, server := range m.HandshakeForServerName {
		handshakeForServerName[sni] = shadowtls.HandshakeConfig{
			Server: M.ParseSocksaddr(server),
			Dialer: N.SystemDialer,
		}
	}

	config := shadowtls.ServiceConfig{
		Version:  m.app.Version,
		Password: m.app.Password,
		Users:    m.app.GetUsers(),
		Handshake: shadowtls.HandshakeConfig{
			Server: M.ParseSocksaddr(m.HandshakeServer),
			Dialer: N.SystemDialer,
		},
		HandshakeForServerName: handshakeForServerName,
		StrictMode:             m.app.StrictMode,
		Logger:                 &app.Logger{Logger: m.logger},
	}

	ln, err := NewListener(l, config)
	if err != nil {
		m.logger.Error(fmt.Sprintf("failed to create shadowtls listener: %v", err))
		return l
	}
	return ln
}

func (m *ListenerWrapper) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.Next() {
		return d.ArgErr()
	}
	if d.NextArg() {
		return d.ArgErr()
	}
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "handshake_server":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.HandshakeServer = d.Val()
		case "handshake_for_server_name":
			args := d.RemainingArgs()
			if len(args) != 2 {
				return d.ArgErr()
			}
			if m.HandshakeForServerName == nil {
				m.HandshakeForServerName = make(map[string]string)
			}
			m.HandshakeForServerName[args[0]] = args[1]
		default:
			return d.ArgErr()
		}
	}
	return nil
}

const listenerConnChannelSize = 64

// Listener wraps a net.Listener with a ShadowTLS service.
// It accepts raw TCP connections, runs the ShadowTLS handshake,
// and delivers unwrapped connections via Accept().
type Listener struct {
	service  *shadowtls.Service
	listener net.Listener
	connCh   chan net.Conn
	closed   chan struct{}
	once     sync.Once
}

// NewListener creates a new ShadowTLS listener wrapping the given net.Listener.
func NewListener(inner net.Listener, config shadowtls.ServiceConfig) (*Listener, error) {
	l := &Listener{
		listener: inner,
		connCh:   make(chan net.Conn, listenerConnChannelSize),
		closed:   make(chan struct{}),
	}
	config.Handler = l
	service, err := shadowtls.NewService(config)
	if err != nil {
		return nil, err
	}
	l.service = service
	go l.acceptLoop()
	return l, nil
}

func (l *Listener) acceptLoop() {
	for {
		conn, err := l.listener.Accept()
		if err != nil {
			select {
			case <-l.closed:
			default:
				l.Close()
			}
			return
		}
		go l.handleConn(conn)
	}
}

func (l *Listener) handleConn(conn net.Conn) {
	source := M.SocksaddrFromNet(conn.RemoteAddr())
	if err := l.service.NewConnection(context.Background(), conn, source, M.Socksaddr{}, nil); err != nil {
		conn.Close()
	}
}

// NewConnectionEx implements N.TCPConnectionHandlerEx.
// It delivers unwrapped connections to Accept().
func (l *Listener) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	select {
	case l.connCh <- conn:
	case <-l.closed:
		if onClose != nil {
			onClose(net.ErrClosed)
		}
		conn.Close()
	}
}

func (l *Listener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.connCh:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *Listener) Close() error {
	l.once.Do(func() {
		close(l.closed)
	})
	return l.listener.Close()
}

func (l *Listener) Addr() net.Addr {
	return l.listener.Addr()
}

var (
	_ caddy.Provisioner     = (*ListenerWrapper)(nil)
	_ caddy.ListenerWrapper = (*ListenerWrapper)(nil)
	_ caddyfile.Unmarshaler = (*ListenerWrapper)(nil)
	_ net.Listener          = (*Listener)(nil)
)
