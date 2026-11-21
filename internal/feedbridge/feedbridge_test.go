package feedbridge

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/policyhook/contractpath"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/policyhook/hook"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func bridge(t *testing.T) *Bridge {
	b, err := New(contractpath.Contracts(t))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// lines writes n decision events of one run through the real v2 sink.
func lines(n int) [][]byte {
	var buf bytes.Buffer
	sink := hook.NewLogSinkV2(&buf, "guard-b", "run-1")
	for i := 0; i < n; i++ {
		sink.Emit("corr-"+string(rune('a'+i%26)), hook.EventPayload{State: "denied", ReasonCode: "TOK-MISSING", Resource: "POST https://guard.test/demo"})
	}
	return bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
}

func events(t *testing.T, srv *httptest.Server, from string) []map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/events?run_id=run-1&from_seq="+from, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out []map[string]any
	scan := bufio.NewScanner(resp.Body)
	scan.Buffer(make([]byte, 64*1024), 64*1024)
	for scan.Scan() {
		if data, ok := strings.CutPrefix(scan.Text(), "data: "); ok {
			var e map[string]any
			if json.Unmarshal([]byte(data), &e) != nil {
				t.Fatal("event not JSON")
			}
			out = append(out, e)
		}
	}
	return out
}

func TestBridgeServesBothVersionsInOrderWithoutDuplicates(t *testing.T) {
	b := bridge(t)
	in := lines(4)
	v1 := []byte(`{"run_id":"run-1","seq":5,"ts":"2026-11-21T12:00:00Z","source":"guard-b","kind":"decision","correlation_id":"c","payload":{"state":"allowed"}}`)
	for _, l := range [][]byte{in[0], in[1], in[1], in[3], v1, []byte("plain text"), []byte(`{"run_id":"run-1","seq":9,"payload":{}}`)} {
		_ = b.Ingest(l)
	}
	srv := httptest.NewServer(b)
	defer srv.Close()
	got := events(t, srv, "0")
	var seqs []float64
	for _, e := range got {
		seqs = append(seqs, e["seq"].(float64))
	}
	// 0, 1, the gap recorded for the missing 2, 3, then the v1 event 5 after a gap for 4.
	if len(got) != 6 || got[2]["kind"] != "gap" || got[3]["version"] != float64(2) || got[5]["version"] != nil || got[4]["kind"] != "gap" {
		t.Fatalf("stream: %v %v", seqs, got)
	}
	resp, err := http.Get(srv.URL + "/snapshot?run_id=run-1")
	if err != nil {
		t.Fatal(err)
	}
	var snap bytes.Buffer
	_, _ = snap.ReadFrom(resp.Body)
	_ = resp.Body.Close()
	c := jsonschema.NewCompiler()
	raw, err := os.ReadFile(filepath.Join(contractpath.Contracts(t), "if01-event.v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	v1doc, _ := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err := c.AddResource("https://github.com/eclipse-xfsc/facis-zero-trust-demonstrator/docs/contracts/if01-event.v1.schema.json", v1doc); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile(filepath.Join(contractpath.Contracts(t), "if01-snapshot.v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := jsonschema.UnmarshalJSON(bytes.NewReader(snap.Bytes()))
	if err := sch.Validate(doc); err != nil || !strings.Contains(snap.String(), `"as_of_seq":5`) {
		t.Fatalf("snapshot %s: %v", snap.String(), err)
	}
	if r, _ := http.Get(srv.URL + "/snapshot?run_id=unknown"); r.StatusCode != http.StatusNotFound {
		t.Fatal("unknown run answered")
	}
}

func TestBridgeKeepsTheLastThousandAndSignalsTheLoss(t *testing.T) {
	b := bridge(t)
	for _, l := range lines(Buffer + 5) {
		if err := b.Ingest(l); err != nil {
			t.Fatal(err)
		}
	}
	srv := httptest.NewServer(b)
	defer srv.Close()
	got := events(t, srv, "0")
	if len(got) != Buffer+1 || got[0]["kind"] != "gap" || got[1]["seq"] != float64(5) {
		t.Fatalf("%d events, first %v", len(got), got[0])
	}
}
