package spectrum

import (
	"github.com/cooldogedev/spectrum-df/internal"
	tr "github.com/cooldogedev/spectrum-df/transport"
	"github.com/cooldogedev/spectrum-df/util"
	"github.com/df-mc/dragonfly/server/session"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
	"log/slog"
	"net"
)

type Listener struct {
	log            *slog.Logger
	authentication util.Authentication
	transport      tr.Transport
}

func NewListener(log *slog.Logger, addr string, authentication util.Authentication, transport tr.Transport) (*Listener, error) {
	if transport == nil {
		transport = tr.NewSpectral()
	}

	if err := transport.Listen(addr); err != nil {
		return nil, err
	}
	return &Listener{
		log:            log,
		authentication: authentication,
		transport:      transport,
	}, nil
}

// Accept ...
func (l *Listener) Accept() (session.Conn, error) {
	c, err := l.transport.Accept()
	if err != nil {
		return nil, err
	}

	var authenticator internal.Authenticator
	if l.authentication != nil {
		authenticator = l.authentication.Authenticate
	}
	log := l.log
	if c2, ok := c.(interface{ RemoteAddr() net.Addr }); ok {
		log = log.With("remote_addr", c2.RemoteAddr())
	}
	return internal.NewConn(log, c, authenticator, packet.NewClientPool())
}

// Disconnect ...
func (l *Listener) Disconnect(conn session.Conn, reason string) error {
	_ = conn.WritePacket(&packet.Disconnect{
		HideDisconnectionScreen: reason == "",
		Message:                 reason,
	})
	return conn.Close()
}

// Close ...
func (l *Listener) Close() error {
	return l.transport.Close()
}
