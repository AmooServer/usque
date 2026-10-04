package cmd

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

func TestSOCKSModesExposeOptionalClientStats(t *testing.T) {
	for _, command := range []*cobra.Command{socksCmd, l4SocksCmd} {
		flag := command.Flags().Lookup("client-stats-file")
		if flag == nil {
			t.Fatalf("%s cannot enable client monitoring", command.Name())
		}
		if flag.DefValue != "" {
			t.Fatalf("%s enabled monitoring without an explicit private file", command.Name())
		}
	}
}

func TestSOCKSModesLeaveClientStatsDisabledByDefault(t *testing.T) {
	for _, command := range []*cobra.Command{socksCmd, l4SocksCmd} {
		collector, err := clientStatsFromCommand(command)
		if err != nil || collector != nil {
			t.Fatalf("%s enabled client monitoring by default: %v", command.Name(), err)
		}
	}
}

func TestSOCKSWithoutMonitoringPreservesStartFailure(t *testing.T) {
	startErr := errors.New("listener failed")
	release := make(chan struct{})
	close(release)
	err := runSOCKSServer(statsTestServer{make(chan struct{}), release, startErr}, nil)
	if !errors.Is(err, startErr) {
		t.Fatalf("legacy start error changed: %v", err)
	}
}

type statsTestServer struct {
	started chan struct{}
	release chan struct{}
	err     error
}

func (s statsTestServer) Start() error {
	close(s.started)
	<-s.release
	return s.err
}

type statsTestCloser struct {
	calls int
	err   error
}

func (c *statsTestCloser) Close() error {
	c.calls++
	return c.err
}

func TestSOCKSStartFailureClosesClientStats(t *testing.T) {
	startErr := errors.New("listener failed")
	flushErr := errors.New("checkpoint failed")
	release := make(chan struct{})
	close(release)
	collector := &statsTestCloser{err: flushErr}
	err := runSOCKSWithSignals(statsTestServer{make(chan struct{}), release, startErr}, collector, make(chan os.Signal))
	if collector.calls != 1 || !errors.Is(err, startErr) || !errors.Is(err, flushErr) {
		t.Fatalf("start failure lost its final checkpoint: calls=%d, err=%v", collector.calls, err)
	}
}

func TestSOCKSSignalFlushesWithoutWaitingForWorkers(t *testing.T) {
	server := statsTestServer{started: make(chan struct{}), release: make(chan struct{})}
	defer close(server.release)
	collector := &statsTestCloser{}
	signals := make(chan os.Signal, 1)
	result := make(chan error, 1)
	go func() { result <- runSOCKSWithSignals(server, collector, signals) }()
	<-server.started
	signals <- os.Interrupt
	select {
	case err := <-result:
		if err != nil || collector.calls != 1 {
			t.Fatalf("shutdown did not publish the final checkpoint: calls=%d, err=%v", collector.calls, err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown waited for untracked SOCKS workers")
	}
}

func TestSOCKSNormalReturnPreservesCheckpointFailure(t *testing.T) {
	flushErr := errors.New("checkpoint failed")
	release := make(chan struct{})
	close(release)
	collector := &statsTestCloser{err: flushErr}
	err := runSOCKSWithSignals(statsTestServer{started: make(chan struct{}), release: release}, collector, make(chan os.Signal))
	if collector.calls != 1 || !errors.Is(err, flushErr) {
		t.Fatalf("checkpoint failure was ignored: calls=%d, err=%v", collector.calls, err)
	}
}

func TestSOCKSSignalPreservesCheckpointFailure(t *testing.T) {
	flushErr := errors.New("checkpoint failed")
	server := statsTestServer{started: make(chan struct{}), release: make(chan struct{})}
	defer close(server.release)
	collector := &statsTestCloser{err: flushErr}
	signals := make(chan os.Signal, 1)
	signals <- os.Interrupt
	err := runSOCKSWithSignals(server, collector, signals)
	if collector.calls != 1 || !errors.Is(err, flushErr) {
		t.Fatalf("signal lost checkpoint failure: calls=%d, err=%v", collector.calls, err)
	}
}
