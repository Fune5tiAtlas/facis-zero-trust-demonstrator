package policyevaluator

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestTSAAdapterPassesValidDecisionsAndFailsClosed(t *testing.T) {
	const guard = "spiffe://zone-b.test/ns/m3/sa/ztd-guard"
	type reply struct {
		answer string
		delay  time.Duration
	}
	var current atomic.Pointer[reply]
	tsa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" || r.URL.Path != "/policy/policies/facis/guard/1.0/evaluation" {
			http.Error(w, "unexpected", http.StatusBadRequest)
			return
		}
		rep := current.Load()
		time.Sleep(rep.delay)
		_, _ = io.WriteString(w, rep.answer)
	}))
	defer tsa.Close()
	var logs bytes.Buffer
	adapter, err := NewTSA(TSAConfig{EvaluationURL: tsa.URL + "/policy/policies/facis/guard/1.0/evaluation", TimeoutMS: 200},
		[]string{guard}, slog.New(slog.NewJSONHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	input := `{"correlation_id":"c-1","source":{"spiffe_id":"spiffe://zone-b.test/ns/m3/sa/p"},"request":{"method":"POST","path":"/demo","host":"h"},"token":{"present":false},"tenant":null}`
	call := func(caller string) (int, string) {
		req := httptest.NewRequest(http.MethodPost, "/decision", strings.NewReader(input))
		req.Header.Set("X-Forwarded-Client-Cert", "URI="+caller)
		rec := httptest.NewRecorder()
		adapter.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	allow := `{"decision":{"allow":true,"rule_id":"m3-report-summary","bundle_revision":"v1","obligations":["substitute_upstream_token"]},"selected":"report:summary"}`
	deny := `{"decision":{"allow":false,"reason_code":"POL-RULE-DENY","rule_id":"m3-scope-withdrawn","bundle_revision":"v2","deny_body":{"error":"access_denied"}}}`
	for name, c := range map[string]struct {
		answer string
		delay  time.Duration
		status int
	}{
		"allow":             {allow, 0, http.StatusOK},
		"deny":              {deny, 0, http.StatusOK},
		"no rule":           {`{"decision":{"allow":true,"bundle_revision":"v1","obligations":["substitute_upstream_token"]}}`, 0, http.StatusServiceUnavailable},
		"no revision":       {`{"decision":{"allow":false,"reason_code":"POL-RULE-DENY","rule_id":"r","deny_body":{"error":"x"}}}`, 0, http.StatusServiceUnavailable},
		"outside contract":  {`{"decision":{"allow":true,"rule_id":"r","bundle_revision":"v1","extra":1}}`, 0, http.StatusServiceUnavailable},
		"no decision":       {`{"request_ok":true}`, 0, http.StatusServiceUnavailable},
		"error result":      {`{"id":"x","kind":0,"message":"policy not found"}`, 0, http.StatusServiceUnavailable},
		"slower than bound": {allow, 400 * time.Millisecond, http.StatusServiceUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			current.Store(&reply{c.answer, c.delay})
			logs.Reset()
			start := time.Now()
			status, body := call(guard)
			if status != c.status {
				t.Fatalf("status %d (%s), want %d", status, body, c.status)
			}
			if time.Since(start) > 350*time.Millisecond {
				t.Fatalf("answered after %v, beyond the bound", time.Since(start))
			}
			var entry map[string]any
			if err := json.Unmarshal(logs.Bytes(), &entry); err != nil || entry["correlation_id"] != "c-1" {
				t.Fatalf("decision not logged: %s", logs.String())
			}
			if c.status == http.StatusOK && (entry["rule_id"] == "" || entry["rule_id"] == nil || entry["bundle_revision"] == nil) {
				t.Fatalf("decision log lacks rule or revision: %s", logs.String())
			}
			if c.status != http.StatusOK && !strings.Contains(body, "POL-PDP-UNAVAILABLE") {
				t.Fatalf("failure body %s", body)
			}
		})
	}
	current.Store(&reply{allow, 0})
	if status, _ := call("spiffe://zone-b.test/ns/m3/sa/intruder"); status != http.StatusForbidden {
		t.Fatalf("unlisted caller: %d", status)
	}
	if _, err := NewTSA(TSAConfig{EvaluationURL: tsa.URL, TimeoutMS: 1000}, []string{guard}, slog.Default()); err == nil {
		t.Fatal("a timeout at the guard's bound accepted")
	}
}
