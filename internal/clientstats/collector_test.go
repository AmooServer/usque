package clientstats

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestCollector(t *testing.T) (*Collector, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "clients.json")
	c, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	})
	return c, path
}

func TestCanonicalPeersSessionsAndDirectionalBytes(t *testing.T) {
	c, _ := newTestCollector(t)
	for _, ip := range []string{"127.0.0.1", "::1", "::ffff:127.0.0.1", "not-an-ip"} {
		s := c.Begin(ip, "tcp")
		s.Upload(900)
		s.Download(800)
		s.End()
	}
	tcp := c.Begin("::ffff:192.0.2.8", "tcp")
	udp := c.Begin("192.0.2.8", "udp")
	tcp.Upload(17)
	udp.Download(29)
	udp.End()
	udp.End()
	snap := c.Snapshot()
	if len(snap.Clients) != 1 {
		t.Fatalf("clients=%+v", snap.Clients)
	}
	row := snap.Clients[0]
	if row.IP != "192.0.2.8" || row.ActiveTCP != 1 || row.ActiveUDP != 0 || row.UploadBytes != 17 || row.DownloadBytes != 29 || row.TotalConnections != 2 || row.LastConnected == 0 || row.LastSeen < row.LastConnected {
		t.Fatalf("row=%+v", row)
	}
	tcp.End()
	// A successful write already in flight may finish after the control ends.
	tcp.Upload(3)
	if c.Snapshot().Clients[0].UploadBytes != 20 {
		t.Fatal("late successful write lost")
	}
}

func TestFinalCheckpointFreezesAndRestartRetainsHistoryOnly(t *testing.T) {
	c, path := newTestCollector(t)
	s := c.Begin("192.0.2.11", "udp")
	s.Upload(31)
	s.Download(41)
	before := c.Snapshot()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	s.Upload(99)
	s.End()
	c.Begin("192.0.2.12", "tcp")
	persisted := readSnapshot(t, path)
	if len(persisted.Clients) != 1 || persisted.Clients[0].ActiveUDP != 0 || persisted.Clients[0].UploadBytes != 31 {
		t.Fatalf("checkpoint=%+v", persisted)
	}
	next, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = next.Close() }()
	after := next.Snapshot()
	if after.MonitoredSince != before.MonitoredSince || after.Clients[0].LastConnected != before.Clients[0].LastConnected || after.Clients[0].TotalConnections != 1 || after.Clients[0].DownloadBytes != 41 || after.Clients[0].ActiveUDP != 0 {
		t.Fatalf("restart=%+v", after)
	}
	if after.SchemaVersion != 1 || after.MaxClients != 4096 || after.PID != os.Getpid() || after.UpdatedAt == 0 || after.ProcessStartedAt == 0 {
		t.Fatalf("metadata=%+v", after)
	}
}

func TestCapacityPreservesRowsAndExplicitOverflow(t *testing.T) {
	c, _ := newTestCollector(t)
	for i := 0; i < 4096; i++ {
		c.Begin(fmt.Sprintf("198.18.%d.%d", i/256, i%256), "tcp").End()
	}
	if c.Snapshot().CapacityReached {
		t.Fatal("capacity marked before an omitted IP")
	}
	s := c.Begin("198.19.0.1", "tcp")
	s.Upload(7)
	s.Download(11)
	s.End()
	c.Begin("198.18.0.0", "udp").End()
	snap := c.Snapshot()
	if len(snap.Clients) != 4096 || !snap.CapacityReached || snap.Overflow.TotalConnections != 1 || snap.Overflow.UploadBytes != 7 || snap.Overflow.DownloadBytes != 11 || snap.Clients[0].TotalConnections == 0 {
		t.Fatal("bounded history/overflow failed")
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentUpdatesAndCloseBoundary(t *testing.T) {
	c, _ := newTestCollector(t)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := c.Begin("192.0.2.20", "tcp")
			for j := 0; j < 100; j++ {
				s.Upload(2)
				s.Download(3)
			}
			s.End()
		}()
	}
	wg.Wait()
	row := c.Snapshot().Clients[0]
	if row.UploadBytes != 6400 || row.DownloadBytes != 9600 || row.TotalConnections != 32 || row.ActiveTCP != 0 {
		t.Fatalf("concurrent=%+v", row)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		s := c.Begin("192.0.2.20", "udp")
		for j := 0; j < 100; j++ {
			s.Upload(1)
		}
		s.End()
	}()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if c.Snapshot().Clients[0].ActiveUDP != 0 {
		t.Fatal("late active mutation")
	}
}

func TestCorruptOrOversizedHistoryIsNotOverwritten(t *testing.T) {
	for _, data := range []string{"{bad", `{"schema_version":1,"clients":[{"ip":"invalid"}]}`, string(make([]byte, MaxBytes+1))} {
		path := filepath.Join(t.TempDir(), "clients.json")
		if err := os.WriteFile(path, []byte(data), 0640); err != nil {
			t.Fatal(err)
		}
		if c, err := New(path); err == nil {
			_ = c.Close()
			t.Fatal("invalid history accepted")
		}
		got, _ := os.ReadFile(path)
		if string(got) != data {
			t.Fatal("invalid history overwritten")
		}
	}
}

func readSnapshot(t *testing.T, path string) Snapshot {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var s Snapshot
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestHistoryRejectsAmbiguousSchemaAndImpossibleTimes(t *testing.T) {
	c, path := newTestCollector(t)
	c.Begin("192.0.2.22", "tcp").End()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	valid, _ := os.ReadFile(path)
	cases := map[string][]byte{}
	cases["duplicate"] = []byte(strings.Replace(string(valid), `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1))
	cases["missing_zero_field"] = []byte(strings.Replace(string(valid), `"download_bytes":0,`, "", 1))
	cases["null_counter"] = []byte(strings.Replace(string(valid), `"download_bytes":0`, `"download_bytes":null`, 1))
	cases["case_alias"] = []byte(strings.Replace(string(valid), `"schema_version"`, `"Schema_Version"`, 1))
	cases["null_clients"] = []byte(strings.Replace(string(valid), `"clients":[`, `"clients":null,"removed":[`, 1))
	for _, kind := range []string{"metadata_order", "row_after_sample", "row_before_monitoring", "future_sample", "false_capacity"} {
		var snapshot Snapshot
		_ = json.Unmarshal(valid, &snapshot)
		switch kind {
		case "metadata_order":
			snapshot.MonitoredSince = snapshot.ProcessStartedAt + 1
		case "row_after_sample":
			snapshot.Clients[0].LastSeen = snapshot.UpdatedAt + 1
		case "row_before_monitoring":
			snapshot.Clients[0].LastConnected = snapshot.MonitoredSince - 1
		case "future_sample":
			snapshot.UpdatedAt = time.Now().Unix() + 600
		case "false_capacity":
			snapshot.CapacityReached = true
		}
		data, _ := json.Marshal(snapshot)
		cases[kind] = data
	}
	for kind, data := range cases {
		t.Run(kind, func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "clients.json")
			if err := os.WriteFile(target, data, 0640); err != nil {
				t.Fatal(err)
			}
			if collector, err := New(target); err == nil {
				_ = collector.Close()
				t.Fatal("invalid history accepted")
			}
			after, _ := os.ReadFile(target)
			if string(after) != string(data) {
				t.Fatal("rejected history was overwritten")
			}
		})
	}
}

func TestCheckpointTimestampNeverPrecedesItsRows(t *testing.T) {
	c, path := newTestCollector(t)
	c.Begin("192.0.2.25", "tcp").End()
	// Model a small backwards wall clock step after a recent operation.
	future := time.Now().Unix() + 2
	c.mu.Lock()
	c.state.ProcessStartedAt = future
	c.state.UpdatedAt = future
	c.clients["192.0.2.25"].LastSeen = future
	c.mu.Unlock()
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	sample := readSnapshot(t, path)
	if sample.UpdatedAt < sample.ProcessStartedAt || sample.UpdatedAt < sample.Clients[0].LastSeen {
		t.Fatal("published impossible timestamp ordering")
	}
}

func TestPeriodicCheckpointPublishesNewUsage(t *testing.T) {
	c, path := newTestCollector(t)
	session := c.Begin("192.0.2.26", "tcp")
	session.Upload(123)
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		sample := readSnapshot(t, path)
		if len(sample.Clients) == 1 && sample.Clients[0].UploadBytes == 123 && sample.Clients[0].ActiveTCP == 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("two-second publisher did not checkpoint usage")
}
