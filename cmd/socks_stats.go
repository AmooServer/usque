package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Diniboy1123/usque/internal/clientstats"
	"github.com/spf13/cobra"
)

func clientStatsFromCommand(command *cobra.Command) (*clientstats.Collector, error) {
	path, err := command.Flags().GetString("client-stats-file")
	if err != nil {
		return nil, fmt.Errorf("failed to get client monitoring setting: %w", err)
	}
	if path == "" {
		return nil, nil
	}
	collector, err := clientstats.New(path)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize client monitoring: %w", err)
	}
	return collector, nil
}

type socksStarter interface {
	Start() error
}

type statsCloser interface {
	Close() error
}

func runSOCKSServer(server socksStarter, collector *clientstats.Collector) error {
	if collector == nil {
		return server.Start()
	}
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	return runSOCKSWithSignals(server, collector, signals)
}

// Shutdown freezes the monitoring sample without waiting for untracked workers.
// Successful writes after that boundary are intentionally outside the sample.
func runSOCKSWithSignals(server socksStarter, collector statsCloser, signals <-chan os.Signal) error {
	result := make(chan error, 1)
	go func() { result <- server.Start() }()
	var err error
	select {
	case err = <-result:
	case <-signals:
	}
	return errors.Join(err, collector.Close())
}
