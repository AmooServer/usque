package internal

import (
	"net"
	"testing"
)

func TestUDPAssociationCopiesLocalTCPAddress(t *testing.T) {
	s := testSOCKSServer(t)
	local := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 903}
	a, err := s.registerUDPAssociation(zeroAssociate(false), &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}, local)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.closeUDPAssociation(a) })
	local.IP[len(local.IP)-1] = 3
	if !a.localIP.Equal(net.IPv4(127, 0, 0, 2)) {
		t.Fatal("UDP association did not retain its own TCP local address")
	}
}
