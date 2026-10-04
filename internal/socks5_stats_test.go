package internal

import (
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/Diniboy1123/usque/internal/clientstats"
	"github.com/txthinking/socks5"
)

func testStats(t *testing.T) *clientstats.Collector {
	t.Helper()
	c, err := clientstats.New(filepath.Join(t.TempDir(), "clients.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestStatsBeginRequiresAuthenticationAndSupportedRequest(t *testing.T) {
	s := testSOCKSServer(t)
	s.cfg.ClientStats = testStats(t)
	peer := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 4242}
	s.beginClientSession(peer, socks5.CmdConnect).End()
	s.cfg.Username, s.cfg.Password = "fixture-user", "fixture-password"
	s.beginClientSession(peer, socks5.CmdBind).End()
	s.beginClientSession(&net.TCPAddr{IP: net.ParseIP("127.0.0.1")}, socks5.CmdConnect).End()
	if len(s.cfg.ClientStats.Snapshot().Clients) != 0 {
		t.Fatal("anonymous, unsupported, or diagnostic request counted")
	}
	a := s.beginClientSession(peer, socks5.CmdConnect)
	b := s.beginClientSession(peer, socks5.CmdUDP)
	row := s.cfg.ClientStats.Snapshot().Clients[0]
	if row.ActiveTCP != 1 || row.ActiveUDP != 1 || row.TotalConnections != 2 {
		t.Fatalf("row=%+v", row)
	}
	a.End()
	b.End()
}

type partialStatsConn struct{ net.Conn }

func (c partialStatsConn) Write(p []byte) (int, error) { return 3, errors.New("fixture partial write") }
func TestTCPStatsCountPartialWritesAndDirection(t *testing.T) {
	s := testSOCKSServer(t)
	stats := testStats(t)
	session := stats.Begin("192.0.2.40", "tcp")
	a, client := net.Pipe()
	b, remote := net.Pipe()
	done := make(chan struct{})
	defer func() { _ = a.Close(); _ = b.Close(); _ = client.Close(); _ = remote.Close(); <-done }()
	go func() { s.relayTCP(a, partialStatsConn{b}, 0, session); close(done) }()
	writeStatsFixture(t, client, []byte("long upload"))
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("partial relay stayed open")
	}
	row := stats.Snapshot().Clients[0]
	if row.UploadBytes != 3 || row.DownloadBytes != 0 {
		t.Fatalf("partial=%+v", row)
	}
}

func TestUDPStatsCreditAuthenticatedControlAndExcludeHeader(t *testing.T) {
	s := testSOCKSServer(t)
	stats := testStats(t)
	s.cfg.ClientStats = stats
	control := stats.Begin("192.0.2.50", "udp")
	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	s.server.UDPConn = listener
	// The source is admitted only through its immutable authenticated session.
	req := zeroAssociate(false)
	assoc, err := s.registerUDPAssociationWithSession(req, client.LocalAddr(), nil, control)
	if err != nil {
		t.Fatal(err)
	}
	defer s.closeUDPAssociation(assoc)
	local, upstream := net.Pipe()
	s.cfg.DialUDP = func(_ context.Context, _, _ string) (net.Conn, error) { return local, nil }
	defer func() { _ = local.Close(); _ = upstream.Close() }()
	upstreamResult := make(chan error, 1)
	go func() {
		data := make([]byte, 4)
		if _, err := io.ReadFull(upstream, data); err != nil {
			upstreamResult <- err
			return
		}
		n, err := upstream.Write([]byte("reply"))
		if err == nil && n != len("reply") {
			err = io.ErrShortWrite
		}
		upstreamResult <- err
	}()
	d := socks5.NewDatagram(socks5.ATYPIPv4, net.ParseIP("192.0.2.80").To4(), []byte{0, 53}, []byte("ping"))
	if err := s.UDPHandle(s.server, client.LocalAddr().(*net.UDPAddr), d); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	wire := make([]byte, 128)
	n, _, err := client.ReadFromUDP(wire)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := socks5.NewDatagramFromBytes(wire[:n])
	if err != nil || string(frame.Data) != "reply" {
		t.Fatal("bad framed reply")
	}
	if err := <-upstreamResult; err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for stats.Snapshot().Clients[0].DownloadBytes != 5 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	row := stats.Snapshot().Clients[0]
	if row.UploadBytes != 4 || row.DownloadBytes != 5 || row.ActiveUDP != 1 || row.TotalConnections != 1 {
		t.Fatalf("UDP=%+v", row)
	}
	rejected := &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: client.LocalAddr().(*net.UDPAddr).Port}
	if err := s.UDPHandle(s.server, rejected, d); err == nil {
		t.Fatal("unassociated traffic accepted")
	}
	if stats.Snapshot().Clients[0].UploadBytes != 4 {
		t.Fatal("unassociated bytes counted")
	}
}

func nonLoopbackTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	var ip net.IP
	for _, address := range addresses {
		candidate, _, err := net.ParseCIDR(address.String())
		if err == nil && candidate.To4() != nil && !candidate.IsLoopback() {
			ip = candidate
			break
		}
	}
	if ip == nil {
		t.Skip("no nonloopback IPv4 fixture available")
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: ip})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	client, err := net.DialTCP("tcp4", &net.TCPAddr{IP: ip}, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	server, err := listener.AcceptTCP()
	if err != nil {
		_ = client.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return server, client
}

func writeStatsFixture(t *testing.T, c net.Conn, payload []byte) {
	t.Helper()
	n, err := c.Write(payload)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(payload) {
		t.Fatal(io.ErrShortWrite)
	}
}

func authenticateStatsClient(t *testing.T, c net.Conn, password string) bool {
	t.Helper()
	if _, err := c.Write([]byte{5, 1, 2}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 2 {
		t.Fatal("authenticated method not required")
	}
	user := "fixture-user"
	auth := append([]byte{1, byte(len(user))}, []byte(user)...)
	auth = append(auth, byte(len(password)))
	auth = append(auth, []byte(password)...)
	if _, err := c.Write(auth); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	return reply[1] == 0
}

func TestRealAuthenticationAndAcceptedTCPAccounting(t *testing.T) {
	stats := testStats(t)
	upstream, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = upstream.Close() }()
	s, err := NewSOCKS5Server(SOCKS5Config{Addr: "127.0.0.1:0", Username: "fixture-user", Password: "fixture-password", TCPOnly: true, ClientStats: stats, DialTCP: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp4", upstream.Addr().String())
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, password := range []string{"wrong-password", "fixture-password"} {
		server, client := nonLoopbackTCPPair(t)
		done := make(chan struct{})
		go func() { s.serveTCP(server); close(done) }()
		accepted := authenticateStatsClient(t, client, password)
		if password == "wrong-password" {
			if accepted {
				t.Fatal("bad auth accepted")
			}
			<-done
			if len(stats.Snapshot().Clients) != 0 {
				t.Fatal("failed auth created a client row")
			}
			continue
		}
		if !accepted {
			t.Fatal("correct auth rejected")
		}
		upstreamResult := make(chan error, 1)
		go func() {
			remote, e := upstream.AcceptTCP()
			if e != nil {
				upstreamResult <- e
				return
			}
			defer func() { _ = remote.Close() }()
			if err := remote.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
				upstreamResult <- err
				return
			}
			payload := make([]byte, 7)
			if _, err := io.ReadFull(remote, payload); err != nil {
				upstreamResult <- err
				return
			}
			if string(payload) != "payload" {
				upstreamResult <- errors.New("fixture upload did not match")
				return
			}
			n, err := remote.Write([]byte("downdata"))
			if err == nil && n != len("downdata") {
				err = io.ErrShortWrite
			}
			upstreamResult <- err
		}()
		writeStatsFixture(t, client, []byte{5, 1, 0, 1, 192, 0, 2, 100, 0, 80})
		reply := make([]byte, 10)
		if _, err := io.ReadFull(client, reply); err != nil || reply[1] != 0 {
			t.Fatal("CONNECT rejected")
		}
		writeStatsFixture(t, client, []byte("payload"))
		download := make([]byte, 8)
		if _, err := io.ReadFull(client, download); err != nil {
			t.Fatal(err)
		}
		if string(download) != "downdata" {
			t.Fatal("fixture download did not match")
		}
		if err := <-upstreamResult; err != nil {
			t.Fatal(err)
		}
		if err := client.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("TCP session did not end")
		}
		snapshot := stats.Snapshot()
		row := snapshot.Clients[0]
		expected := server.RemoteAddr().(*net.TCPAddr).IP.String()
		if len(snapshot.Clients) != 1 || row.IP != expected || row.UploadBytes != 7 || row.DownloadBytes != 8 || row.TotalConnections != 1 || row.ActiveTCP != 0 {
			t.Fatalf("authenticated TCP row=%+v", row)
		}
	}
}

func TestRealAuthenticatedUDPControlCountsOneSessionAndNoControlBytes(t *testing.T) {
	stats := testStats(t)
	s, err := NewSOCKS5Server(SOCKS5Config{Addr: "127.0.0.1:0", Username: "fixture-user", Password: "fixture-password", ClientStats: stats, DialTCP: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("not used") }, DialUDP: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("not used") }})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	s.server.UDPConn = listener
	server, client := nonLoopbackTCPPair(t)
	done := make(chan struct{})
	go func() { s.serveTCP(server); close(done) }()
	if !authenticateStatsClient(t, client, "fixture-password") {
		t.Fatal("auth rejected")
	}
	writeStatsFixture(t, client, []byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil || reply[1] != 0 {
		t.Fatal("UDP control rejected")
	}
	row := stats.Snapshot().Clients[0]
	if row.ActiveUDP != 1 || row.ActiveTCP != 0 || row.TotalConnections != 1 {
		t.Fatalf("control=%+v", row)
	}
	writeStatsFixture(t, client, []byte("keepalive"))
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("UDP control did not end")
	}
	row = stats.Snapshot().Clients[0]
	if row.ActiveUDP != 0 || row.UploadBytes != 0 || row.DownloadBytes != 0 {
		t.Fatalf("control bytes counted: %+v", row)
	}
}

func TestMalformedUnauthenticatedAndRejectedRequestsCannotCreateRows(t *testing.T) {
	for _, kind := range []string{"http", "no_auth", "unsupported", "malformed", "failed_dial", "invalid_udp_source"} {
		t.Run(kind, func(t *testing.T) {
			stats := testStats(t)
			s, err := NewSOCKS5Server(SOCKS5Config{Addr: "127.0.0.1:0", Username: "fixture-user", Password: "fixture-password", ClientStats: stats, DialTCP: func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("fixture dial rejected")
			}, DialUDP: func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("fixture dial rejected")
			}})
			if err != nil {
				t.Fatal(err)
			}
			server, client := nonLoopbackTCPPair(t)
			done := make(chan struct{})
			go func() { s.serveTCP(server); close(done) }()
			switch kind {
			case "http":
				writeStatsFixture(t, client, []byte("GET / HTTP/1.0\r\n\r\n"))
			case "no_auth":
				writeStatsFixture(t, client, []byte{5, 1, 0})
			default:
				if !authenticateStatsClient(t, client, "fixture-password") {
					t.Fatal("fixture auth rejected")
				}
				switch kind {
				case "unsupported":
					writeStatsFixture(t, client, []byte{5, 2, 0, 1, 192, 0, 2, 99, 0, 80})
				case "malformed":
					writeStatsFixture(t, client, []byte{5, 1, 0, 99})
				case "failed_dial":
					writeStatsFixture(t, client, []byte{5, 1, 0, 1, 192, 0, 2, 99, 0, 80})
				case "invalid_udp_source":
					writeStatsFixture(t, client, []byte{5, 3, 0, 1, 192, 0, 2, 99, 0, 80})
				}
			}
			// Drain any bounded protocol error reply so the handler can finish.
			if _, err := io.Copy(io.Discard, client); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, syscall.ECONNRESET) {
				t.Fatal(err)
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("rejected session stayed open")
			}
			if len(stats.Snapshot().Clients) != 0 || stats.Snapshot().Overflow.TotalConnections != 0 {
				t.Fatal("rejected request created usage")
			}
		})
	}
}

func TestUDPStatsCountPartialUploadEvenWhenFlowFails(t *testing.T) {
	s := testSOCKSServer(t)
	stats := testStats(t)
	control := stats.Begin("192.0.2.51", "udp")
	peer := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 43001}
	association, err := s.registerUDPAssociationWithSession(zeroAssociate(false), peer, nil, control)
	if err != nil {
		t.Fatal(err)
	}
	defer s.closeUDPAssociation(association)
	local, remote := net.Pipe()
	defer func() { _ = remote.Close() }()
	s.cfg.DialUDP = func(context.Context, string, string) (net.Conn, error) { return partialStatsConn{local}, nil }
	datagram := socks5.NewDatagram(socks5.ATYPIPv4, net.ParseIP("192.0.2.80").To4(), []byte{0, 53}, []byte("payload"))
	if err := s.UDPHandle(s.server, peer, datagram); err == nil {
		t.Fatal("partial UDP write accepted")
	}
	row := stats.Snapshot().Clients[0]
	if row.UploadBytes != 3 || row.DownloadBytes != 0 {
		t.Fatalf("partial UDP=%+v", row)
	}
}
