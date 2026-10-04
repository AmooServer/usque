package internal

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/txthinking/socks5"
)

func TestUDPReplyPreservesTCPAssociationLocalIP(t *testing.T) {
	s := testSOCKSServer(t)
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	s.server.UDPConn = listener
	client := udpSocket(t)
	a, err := s.registerUDPAssociation(zeroAssociate(false), &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 903})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.closeUDPAssociation(a) })
	upstream, echo := net.Pipe()
	t.Cleanup(func() { _ = upstream.Close(); _ = echo.Close() })
	s.cfg.DialUDP = func(context.Context, string, string) (net.Conn, error) { return upstream, nil }
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 100)
		n, err := echo.Read(buf)
		if err == nil {
			_, _ = echo.Write(buf[:n])
		}
	}()
	d := socks5.NewDatagram(socks5.ATYPIPv4, []byte{192, 0, 2, 1}, []byte{0, 53}, []byte("reply"))
	if err := s.UDPHandle(s.server, client.LocalAddr().(*net.UDPAddr), d); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 100)
	n, source, err := client.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !source.IP.Equal(net.IPv4(127, 0, 0, 2)) {
		t.Fatal("UDP reply used an address different from its TCP association")
	}
	got, err := socks5.NewDatagramFromBytes(buf[:n])
	if err != nil || string(got.Data) != "reply" {
		t.Fatal("UDP reply payload changed")
	}
	<-done
}
