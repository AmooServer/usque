package supervisor

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/Diniboy1123/usque/internal/socksauth"
	"github.com/txthinking/socks5"
)

// authenticatedSOCKSDial offers only username/password, so health cannot silently
// accept an anonymous listener. The existing client keeps hostname DNS remote.
func authenticatedSOCKSDial(ctx context.Context, proxyAddress, network, address string, credentials socksauth.Credentials) (net.Conn, error) {
	if network != "tcp" {
		return nil, errors.New("authenticated SOCKS health requires TCP")
	}
	client, err := socks5.NewClient(proxyAddress, credentials.Username, credentials.Password, 0, 0)
	if err != nil {
		return nil, errors.New("create authenticated SOCKS health client")
	}
	var raw net.Conn
	stop := func() bool { return true }
	client.DialTCP = func(_ string, _ string, target string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", target)
		if err != nil {
			return nil, err
		}
		raw = conn
		if deadline, ok := ctx.Deadline(); ok {
			if err := conn.SetDeadline(deadline); err != nil {
				_ = conn.Close()
				return nil, err
			}
		}
		stop = context.AfterFunc(ctx, func() { _ = conn.Close() })
		return conn, nil
	}
	_, err = client.Dial("tcp", address)
	stop()
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		if raw != nil {
			_ = raw.Close()
		}
		// Do not propagate third-party negotiation errors with credential material.
		return nil, errors.New("authenticated SOCKS health connection failed")
	}
	if err := raw.SetDeadline(time.Time{}); err != nil {
		_ = raw.Close()
		return nil, errors.New("authenticated SOCKS health connection failed")
	}
	return raw, nil
}
