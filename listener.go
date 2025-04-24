package spectrum

import (
	"errors"
	"github.com/cooldogedev/spectrum-df/internal"
	tr "github.com/cooldogedev/spectrum-df/transport"
	"github.com/cooldogedev/spectrum-df/util"
	"github.com/df-mc/dragonfly/server/session"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
	"io"
	"log/slog"
	"net"
	"sync"
)

type Listener struct {
	log            *slog.Logger
	authentication util.Authentication
	transport      tr.Transport
	chunkRadius    int

	incoming chan *internal.Conn
	closed   bool
	closeMu  sync.Mutex
}

func NewListener(log *slog.Logger, addr string, authentication util.Authentication, transport tr.Transport) (*Listener, error) {
	if transport == nil {
		transport = tr.NewSpectral()
	}

	if err := transport.Listen(addr); err != nil {
		return nil, err
	}
	l := &Listener{
		log:            log,
		authentication: authentication,
		transport:      transport,
		chunkRadius:    16,
		incoming:       make(chan *internal.Conn, 64),
		closed:         false,
	}

	go func() {
		for {
			if err := l.internalAccept(); err != nil {
				l.log.Error("failed to internal accept connection", "err", err)
				return
			}
		}
	}()

	return l, nil
}

// SetChunkRadius sets the chunk radius for the listener.
func (l *Listener) SetChunkRadius(radius int) {
	l.chunkRadius = radius
}

// internalAccept ...
func (l *Listener) internalAccept() error {
	c, err := l.transport.Accept()
	if err != nil {
		return err
	}

	var addr net.Addr
	if c2, ok := c.(interface{ RemoteAddr() net.Addr }); ok {
		addr = c2.RemoteAddr()
	}

	go func() {
		conn, err := l.authenticateConn(addr, c)
		if err != nil {
			l.log.Error("failed to authenticate connection", "remote_addr", addr, "err", err)
			return
		}

		l.closeMu.Lock()
		if !l.closed {
			l.incoming <- conn
		}
		l.closeMu.Unlock()
	}()
	return nil
}

// authenticateConn ...
func (l *Listener) authenticateConn(addr net.Addr, c io.ReadWriteCloser) (*internal.Conn, error) {
	var authenticator internal.Authenticator
	if l.authentication != nil {
		authenticator = l.authentication.Authenticate
	}
	return internal.NewConn(l.log.With("remote_addr", addr), c, authenticator, packet.NewClientPool(), l.chunkRadius)
}

// Accept ...
func (l *Listener) Accept() (session.Conn, error) {
	conn := <-l.incoming
	if conn == nil {
		return nil, io.EOF
	}
	conn.Respond()
	return conn, nil
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
	l.closeMu.Lock()
	defer l.closeMu.Unlock()
	if l.closed {
		return errors.New("listener already closed")
	}
	l.closed = true
	close(l.incoming)
	return l.transport.Close()
}
