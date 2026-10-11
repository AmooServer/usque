package cmd

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/Diniboy1123/usque/internal"
)

func TestAcceptLoopStopsWhenListenerClosed(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- acceptLoop(l, "test", func(net.Conn) {}) }()
	_ = l.Close()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("acceptLoop err=%v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("acceptLoop kept spinning after listener close")
	}
}

func TestHandleConnectionPropagatesLocalEOF(t *testing.T) {
	remote, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = remote.Close() }()
	go func() { // replies only after the forwarder half-closes its side
		c, err := remote.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_, _ = io.Copy(io.Discard, c)
		_, _ = c.Write([]byte("done"))
	}()
	front, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = front.Close() }()
	addr := remote.Addr().(*net.TCPAddr)
	go func() {
		server, err := front.Accept()
		if err == nil {
			handleConnection(server, internal.PortMapping{RemoteIP: "127.0.0.1", RemotePort: addr.Port}, true, nil)
		}
	}()
	client, err := net.Dial("tcp", front.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	_ = client.(*net.TCPConn).CloseWrite() // local EOF must reach the remote
	got, err := io.ReadAll(client)
	if err != nil || string(got) != "done" {
		t.Fatalf("reply=%q err=%v", got, err)
	}
}
