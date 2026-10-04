// Package clientstats records bounded SOCKS payload monitoring samples.
package clientstats

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const MaxClients = 4096
const MaxBytes = 2 * 1024 * 1024

type Client struct {
	IP               string `json:"ip"`
	ActiveTCP        uint64 `json:"active_tcp"`
	ActiveUDP        uint64 `json:"active_udp"`
	UploadBytes      uint64 `json:"upload_bytes"`
	DownloadBytes    uint64 `json:"download_bytes"`
	TotalConnections uint64 `json:"total_connections"`
	LastConnected    int64  `json:"last_connected"`
	LastSeen         int64  `json:"last_seen"`
}
type Overflow struct {
	UploadBytes      uint64 `json:"upload_bytes"`
	DownloadBytes    uint64 `json:"download_bytes"`
	TotalConnections uint64 `json:"total_connections"`
}
type Snapshot struct {
	SchemaVersion    int      `json:"schema_version"`
	PID              int      `json:"pid"`
	ProcessStartedAt int64    `json:"process_started_at"`
	UpdatedAt        int64    `json:"updated_at"`
	MonitoredSince   int64    `json:"monitored_since"`
	MaxClients       int      `json:"max_clients"`
	CapacityReached  bool     `json:"capacity_reached"`
	Clients          []Client `json:"clients"`
	Overflow         Overflow `json:"overflow"`
}
type Collector struct {
	mu        sync.Mutex
	flushMu   sync.Mutex
	path      string
	clients   map[string]*Client
	state     Snapshot
	closed    bool
	stop      chan struct{}
	done      chan struct{}
	lock      *os.File
	closeOnce sync.Once
	closeErr  error
}

// Session remains valid for late completed writes until the collector closes.
type Session struct {
	collector *Collector
	row       *Client
	kind      string
	ended     bool // protected by collector.mu
}

func safeError() error { return errors.New("SOCKS client statistics are unavailable") }

func New(path string) (*Collector, error) {
	if !filepath.IsAbs(path) || validateDirectory(filepath.Dir(path)) != nil {
		return nil, safeError()
	}
	lock, err := lockPath(path + ".lock")
	if err != nil {
		return nil, safeError()
	}
	failed := true
	defer func() {
		if failed {
			releaseLock(lock)
		}
	}()
	now := time.Now().Unix()
	c := &Collector{path: path, clients: make(map[string]*Client), stop: make(chan struct{}), done: make(chan struct{}), lock: lock,
		state: Snapshot{SchemaVersion: 1, PID: os.Getpid(), ProcessStartedAt: now, UpdatedAt: now, MonitoredSince: now, MaxClients: MaxClients}}
	f, err := readSecure(path)
	if err == nil {
		data, readErr := io.ReadAll(io.LimitReader(f, MaxBytes+1))
		_ = f.Close()
		if readErr != nil || len(data) > MaxBytes {
			return nil, safeError()
		}
		old, decodeErr := decodeSnapshot(data)
		if decodeErr != nil || validateSnapshot(old) != nil {
			return nil, safeError()
		}
		c.state.MonitoredSince = old.MonitoredSince
		c.state.CapacityReached = old.CapacityReached
		c.state.Overflow = old.Overflow
		c.state.ProcessStartedAt = max(now, old.UpdatedAt)
		c.state.UpdatedAt = c.state.ProcessStartedAt
		for _, row := range old.Clients {
			row.ActiveTCP = 0
			row.ActiveUDP = 0
			c.clients[row.IP] = &row
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, safeError()
	}
	if err := c.Flush(); err != nil {
		return nil, err
	}
	failed = false
	go func() {
		defer close(c.done)
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-c.stop:
				return
			case <-ticker.C:
				if c.Flush() != nil {
					log.Print("SOCKS client statistics checkpoint failed")
				}
			}
		}
	}()
	return c, nil
}

func canonicalIP(raw string) (string, bool) {
	ip, err := netip.ParseAddr(raw)
	if err != nil || ip.Zone() != "" || !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() {
		return "", false
	}
	ip = ip.Unmap()
	if ip.IsLoopback() {
		return "", false
	}
	return ip.String(), true
}
func validateSnapshot(s Snapshot) error {
	if s.SchemaVersion != 1 || s.MaxClients != MaxClients || len(s.Clients) > MaxClients || s.MonitoredSince <= 0 || s.PID <= 0 || s.MonitoredSince > s.ProcessStartedAt || s.ProcessStartedAt > s.UpdatedAt || s.UpdatedAt > time.Now().Unix()+5 {
		return safeError()
	}
	seen := make(map[string]bool)
	for _, row := range s.Clients {
		ip, ok := canonicalIP(row.IP)
		if !ok || ip != row.IP || seen[ip] || row.TotalConnections == 0 || row.LastConnected < s.MonitoredSince || row.LastSeen < row.LastConnected || row.LastSeen > s.UpdatedAt || row.ActiveTCP > row.TotalConnections || row.ActiveUDP > row.TotalConnections-row.ActiveTCP {
			return safeError()
		}
		seen[ip] = true
	}
	if (s.Overflow.TotalConnections != 0 || s.Overflow.UploadBytes != 0 || s.Overflow.DownloadBytes != 0) && !s.CapacityReached {
		return safeError()
	}
	if s.CapacityReached && len(s.Clients) != MaxClients {
		return safeError()
	}
	if s.Overflow.TotalConnections == 0 && (s.Overflow.UploadBytes != 0 || s.Overflow.DownloadBytes != 0) {
		return safeError()
	}
	return nil
}

// Reject duplicate, missing, case-aliased and null keys before decoding counters.
// History is never overwritten when its schema or timestamps are ambiguous.
func strictObject(data []byte, keys []string) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, safeError()
	}
	allowed := make(map[string]bool, len(keys))
	for _, key := range keys {
		allowed[key] = true
	}
	fields := make(map[string]json.RawMessage, len(keys))
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, safeError()
		}
		key, ok := token.(string)
		if !ok || !allowed[key] || fields[key] != nil {
			return nil, safeError()
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, safeError()
		}
		fields[key] = value
	}
	if _, err := decoder.Token(); err != nil {
		return nil, safeError()
	}
	if decoder.Decode(new(any)) != io.EOF || len(fields) != len(keys) {
		return nil, safeError()
	}
	return fields, nil
}
func decodeSnapshot(data []byte) (Snapshot, error) {
	var snapshot Snapshot
	fields, err := strictObject(data, []string{"schema_version", "pid", "process_started_at", "updated_at", "monitored_since", "max_clients", "capacity_reached", "clients", "overflow"})
	if err != nil {
		return snapshot, err
	}
	var clients []json.RawMessage
	if json.Unmarshal(fields["clients"], &clients) != nil || len(clients) > MaxClients {
		return snapshot, safeError()
	}
	for _, row := range clients {
		if _, err := strictObject(row, []string{"ip", "active_tcp", "active_udp", "upload_bytes", "download_bytes", "total_connections", "last_connected", "last_seen"}); err != nil {
			return snapshot, err
		}
	}
	if _, err := strictObject(fields["overflow"], []string{"upload_bytes", "download_bytes", "total_connections"}); err != nil {
		return snapshot, err
	}
	if json.Unmarshal(data, &snapshot) != nil {
		return snapshot, safeError()
	}
	return snapshot, nil
}
func increment(value *uint64, n uint64) {
	if math.MaxUint64-*value < n {
		*value = math.MaxUint64
	} else {
		*value += n
	}
}
func (c *Collector) Begin(raw, kind string) *Session {
	if c == nil || (kind != "tcp" && kind != "udp") {
		return nil
	}
	ip, ok := canonicalIP(raw)
	if !ok {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	row := c.clients[ip]
	if row == nil {
		if len(c.clients) == MaxClients {
			c.state.CapacityReached = true
			increment(&c.state.Overflow.TotalConnections, 1)
			return &Session{collector: c, kind: kind}
		}
		row = &Client{IP: ip}
		c.clients[ip] = row
	}
	now := max(time.Now().Unix(), row.LastSeen, c.state.ProcessStartedAt)
	increment(&row.TotalConnections, 1)
	row.LastConnected = now
	row.LastSeen = now
	if kind == "tcp" {
		increment(&row.ActiveTCP, 1)
	} else {
		increment(&row.ActiveUDP, 1)
	}
	return &Session{collector: c, row: row, kind: kind}
}
func (s *Session) Upload(n int)   { s.add(n, true) }
func (s *Session) Download(n int) { s.add(n, false) }
func (s *Session) add(n int, upload bool) {
	if s == nil || n <= 0 {
		return
	}
	c := s.collector
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	if s.row == nil {
		if upload {
			increment(&c.state.Overflow.UploadBytes, uint64(n))
		} else {
			increment(&c.state.Overflow.DownloadBytes, uint64(n))
		}
		return
	}
	if upload {
		increment(&s.row.UploadBytes, uint64(n))
	} else {
		increment(&s.row.DownloadBytes, uint64(n))
	}
	if now := time.Now().Unix(); now > s.row.LastSeen {
		s.row.LastSeen = now
	}
}
func (s *Session) End() {
	if s == nil {
		return
	}
	c := s.collector
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || s.ended {
		return
	}
	s.ended = true
	if s.row == nil {
		return
	}
	if s.kind == "tcp" {
		s.row.ActiveTCP--
	} else {
		s.row.ActiveUDP--
	}
	if now := time.Now().Unix(); now > s.row.LastSeen {
		s.row.LastSeen = now
	}
}
func (c *Collector) Snapshot() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.state
	s.Clients = make([]Client, 0, len(c.clients))
	for _, row := range c.clients {
		s.Clients = append(s.Clients, *row)
	}
	sort.Slice(s.Clients, func(i, j int) bool { return s.Clients[i].IP < s.Clients[j].IP })
	return s
}
func (c *Collector) Flush() error {
	return c.flush(false)
}
func (c *Collector) flush(final bool) error {
	c.flushMu.Lock()
	defer c.flushMu.Unlock()
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed && !final {
		return nil
	}
	snapshot := c.Snapshot()
	snapshot.UpdatedAt = max(time.Now().Unix(), snapshot.UpdatedAt, snapshot.ProcessStartedAt)
	for _, row := range snapshot.Clients {
		snapshot.UpdatedAt = max(snapshot.UpdatedAt, row.LastSeen, row.LastConnected)
	}
	data, err := json.Marshal(snapshot)
	if err != nil || len(data) > MaxBytes {
		return safeError()
	}
	if err := atomicWrite(c.path, append(data, '\n')); err != nil {
		return safeError()
	}
	c.mu.Lock()
	c.state.UpdatedAt = snapshot.UpdatedAt
	c.mu.Unlock()
	return nil
}
func (c *Collector) Close() error {
	if c == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		for _, row := range c.clients {
			row.ActiveTCP = 0
			row.ActiveUDP = 0
		}
		c.mu.Unlock()
		close(c.stop)
		<-c.done
		c.closeErr = c.flush(true)
		releaseLock(c.lock)
	})
	return c.closeErr
}
func atomicWrite(path string, data []byte) error {
	if validateDirectory(filepath.Dir(path)) != nil {
		return safeError()
	}
	if f, err := readSecure(path); err == nil {
		_ = f.Close()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".clients-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if err := f.Chmod(0640); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}
