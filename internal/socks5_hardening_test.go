package internal

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/txthinking/socks5"
)

func TestNewSOCKS5ServerRejectsHalfCredentials(t *testing.T) {
	dial := (&net.Dialer{}).DialContext
	for _, c := range [][2]string{{"user", ""}, {"", "pass"}} {
		_, err := NewSOCKS5Server(SOCKS5Config{Addr: "127.0.0.1:0", DialTCP: dial, DialUDP: dial, Username: c[0], Password: c[1]})
		if err == nil {
			t.Fatalf("accepted credentials %q/%q", c[0], c[1])
		}
	}
}

func TestUDPAssociateSpecificIPPortZeroIsPending(t *testing.T) {
	s := testSOCKSServer(t)
	peer := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1234}
	r := &socks5.Request{Cmd: socks5.CmdUDP, Atyp: socks5.ATYPIPv4, DstAddr: peer.IP.To4(), DstPort: []byte{0, 0}}
	a, err := s.registerUDPAssociation(r, peer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.closeUDPAssociation(a) })
	got, ok := s.claimUDPAssociation(&net.UDPAddr{IP: peer.IP, Port: 40000})
	if !ok || got != a {
		t.Fatal("datagram from a different port did not claim the pending association")
	}
	if _, ok := s.claimUDPAssociation(&net.UDPAddr{IP: net.ParseIP("192.0.2.11"), Port: 40000}); ok {
		t.Fatal("datagram from another IP was accepted")
	}
}

func TestUDPRelaysPerAssociationAreCapped(t *testing.T) {
	s := testSOCKSServer(t)
	peer := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1234}
	a, err := s.registerUDPAssociation(zeroAssociate(false), peer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.closeUDPAssociation(a) })
	addr := &net.UDPAddr{IP: peer.IP, Port: 4321}
	if _, ok := s.claimUDPAssociation(addr); !ok {
		t.Fatal("failed to claim association")
	}
	release := make(chan struct{})
	s.cfg.DialUDP = func(ctx context.Context, _, _ string) (net.Conn, error) {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil, context.Canceled
	}
	var wg sync.WaitGroup
	errs := make(chan error, maxUDPRelaysPerAssociation+8)
	for i := range maxUDPRelaysPerAssociation + 8 {
		d := socks5.NewDatagram(socks5.ATYPDomain, []byte("host"+string(rune('a'+i%26))+string(rune('a'+i/26))+".invalid"), []byte{0, 53}, []byte("x"))
		wg.Go(func() { errs <- s.UDPHandle(s.server, addr, d) })
	}
	// Excess flows are refused immediately while the capped ones are still dialing.
	for range 8 {
		select {
		case err := <-errs:
			if err == nil {
				t.Fatal("expected cap error")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("excess flows were not rejected")
		}
	}
	if n := a.relays.Load(); n != maxUDPRelaysPerAssociation {
		t.Fatalf("association holds %d relays", n)
	}
	close(release)
	wg.Wait()
	if n := a.relays.Load(); n != 0 {
		t.Fatalf("association leaked %d relays", n)
	}
}
