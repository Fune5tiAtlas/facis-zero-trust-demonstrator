// Package feedbridge is the IF-01 feed bridge (docs/contracts/if01-feed.v1.openapi.yaml): it takes
// the components' IF-01 log lines, v1 and v2 alike, and serves a run's snapshot and its events as
// server-sent events.
//
// Sequencing is the producers': each process names its own run and numbers its events from 0
// (hook.LogSink), so (run_id, seq) is unique and the bridge never renumbers. A line repeating a
// seq already taken is a duplicate of at-least-once delivery and is dropped; a seq that skips
// ahead records a gap event (VIS-STALE) under the first missing number. Each run keeps its last
// 1000 events; a reader asking for older ones receives a gap event first.
package feedbridge

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Buffer is the number of events a run keeps.
const Buffer = 1000

type meta struct {
	Version int    `json:"version"`
	RunID   string `json:"run_id"`
	Seq     uint64 `json:"seq"`
	TS      string `json:"ts"`
	Source  string `json:"source"`
	Payload struct {
		State      string `json:"state"`
		ReasonCode string `json:"reason_code"`
	} `json:"payload"`
}

type stored struct {
	seq uint64
	raw json.RawMessage
}

type panel struct {
	State      string `json:"state"`
	ReasonCode string `json:"reason_code,omitempty"`
	TS         string `json:"ts"`
}

type run struct {
	events []stored
	next   uint64 // the next seq expected
	panels map[string]panel
}

// Bridge holds the runs. Safe for concurrent use.
type Bridge struct {
	mu      sync.Mutex
	runs    map[string]*run
	v1, v2  *jsonschema.Schema
	changed chan struct{}
}

// New compiles the v1 and v2 event schemas from the contracts directory.
func New(contracts string) (*Bridge, error) {
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	v1, err := c.Compile(filepath.Join(contracts, "if01-event.v1.schema.json"))
	if err != nil {
		return nil, err
	}
	v2, err := c.Compile(filepath.Join(contracts, "if01-event.v2.schema.json"))
	if err != nil {
		return nil, err
	}
	return &Bridge{runs: map[string]*run{}, v1: v1, v2: v2, changed: make(chan struct{})}, nil
}

// ErrNotEvent is a line that is not a valid IF-01 event of either version.
var ErrNotEvent = errors.New("not an IF-01 event")

// Ingest takes one log line. A line that is not an IF-01 event is refused with ErrNotEvent.
func (b *Bridge) Ingest(line []byte) error {
	line = bytes.TrimSpace(line)
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(line))
	if err != nil {
		return ErrNotEvent
	}
	var m meta
	if json.Unmarshal(line, &m) != nil {
		return ErrNotEvent
	}
	schema := b.v1
	if m.Version == 2 {
		schema = b.v2
	}
	if schema.Validate(doc) != nil {
		return ErrNotEvent
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	r := b.runs[m.RunID]
	if r == nil {
		r = &run{panels: map[string]panel{}}
		b.runs[m.RunID] = r
	} else if m.Seq < r.next {
		return nil // a duplicate
	}
	if len(r.events) > 0 && m.Seq > r.next {
		r.add(stored{r.next, gap(m.RunID, r.next, fmt.Sprintf("events %d to %d never arrived", r.next, m.Seq-1))})
	}
	r.add(stored{m.Seq, json.RawMessage(append([]byte(nil), line...))})
	r.next = m.Seq + 1
	r.panels[m.Source] = panel{State: m.Payload.State, ReasonCode: m.Payload.ReasonCode, TS: m.TS}
	close(b.changed)
	b.changed = make(chan struct{})
	return nil
}

func (r *run) add(e stored) {
	r.events = append(r.events, e)
	if len(r.events) > Buffer {
		r.events = append([]stored(nil), r.events[len(r.events)-Buffer:]...)
	}
}

func gap(runID string, seq uint64, detail string) json.RawMessage {
	raw, _ := json.Marshal(map[string]any{"run_id": runID, "seq": seq, "ts": time.Now().UTC().Format(time.RFC3339Nano), "source": "feed-bridge",
		"kind": "gap", "payload": map[string]string{"state": "gap", "reason_code": "VIS-STALE", "detail": detail}})
	return raw
}

// Snapshot is a run's state as of its last seq, or false for an unknown run.
func (b *Bridge) Snapshot(runID string) (map[string]any, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	r := b.runs[runID]
	if r == nil {
		return nil, false
	}
	panels := map[string]panel{}
	for k, v := range r.panels {
		panels[k] = v
	}
	return map[string]any{"run_id": runID, "as_of_seq": r.next - 1, "panels": panels}, true
}

// since returns the run's events from seq on, a gap event first when some are no longer kept, the
// next seq to ask for, and a channel closed on the next ingest.
func (b *Bridge) since(runID string, from uint64) ([]json.RawMessage, uint64, <-chan struct{}, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	r := b.runs[runID]
	if r == nil {
		return nil, 0, nil, false
	}
	var out []json.RawMessage
	if len(r.events) > 0 && from < r.events[0].seq {
		out = append(out, gap(runID, from, fmt.Sprintf("events %d to %d are no longer buffered", from, r.events[0].seq-1)))
	}
	for _, e := range r.events {
		if e.seq >= from {
			out = append(out, e.raw)
		}
	}
	if r.next > from {
		from = r.next
	}
	return out, from, b.changed, true
}

// ServeHTTP serves GET /snapshot and GET /events (the IF-01 feed API).
func (b *Bridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	runID := r.URL.Query().Get("run_id")
	if r.Method != http.MethodGet || runID == "" {
		http.NotFound(w, r)
		return
	}
	switch r.URL.Path {
	case "/snapshot":
		snap, ok := b.Snapshot(runID)
		if !ok {
			http.Error(w, "unknown run", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(snap)
	case "/events":
		from, err := strconv.ParseUint(r.URL.Query().Get("from_seq"), 10, 64)
		if err != nil {
			http.Error(w, "from_seq required", http.StatusBadRequest)
			return
		}
		b.stream(w, r, runID, from)
	default:
		http.NotFound(w, r)
	}
}

func (b *Bridge) stream(w http.ResponseWriter, r *http.Request, runID string, from uint64) {
	events, next, changed, ok := b.since(runID, from)
	if !ok {
		http.Error(w, "unknown run", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	flusher, _ := w.(http.Flusher)
	for {
		for _, e := range events {
			var m meta
			_ = json.Unmarshal(e, &m)
			if _, err := fmt.Fprintf(w, "id: %d\ndata: %s\n\n", m.Seq, e); err != nil {
				return
			}
		}
		if flusher != nil {
			flusher.Flush()
		}
		select {
		case <-r.Context().Done():
			return
		case <-changed:
		}
		events, next, changed, _ = b.since(runID, next)
	}
}
