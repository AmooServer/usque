package api

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"
)

// A silent UDP endpoint lets concurrent callers be told apart by QUIC source port:
// one shared dial means one client socket.
func TestGetOrCreateClientConnCollapsesConcurrentDials(t *testing.T) {
	sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sink.Close() }()
	var mu sync.Mutex
	sources := map[string]bool{}
	go func() {
		buf := make([]byte, 2048)
		for {
			_, from, err := sink.ReadFromUDP(buf)
			if err != nil {
				return
			}
			mu.Lock()
			sources[from.String()] = true
			mu.Unlock()
		}
	}()
	p, err := NewL4Proxy(L4ProxyConfig{
		TLSConfig: &tls.Config{NextProtos: []string{"h3"}, InsecureSkipVerify: true},
		Endpoint:  sink.LocalAddr().(*net.UDPAddr),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if _, err := p.getOrCreateClientConn(ctx); err == nil {
				t.Error("dial to a silent endpoint succeeded")
			}
		})
	}
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if len(sources) != 1 {
		t.Fatalf("concurrent callers used %d client sockets, want 1", len(sources))
	}
}
