package policyevaluator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/meshcaller"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/policyhook/hook"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/tsabundle"
)

// TSAConfig selects the XFSC TSA policy service as the decision engine.
type TSAConfig struct {
	// EvaluationURL is the policy's TSA evaluation endpoint, e.g.
	// http://tsa-policy-engine:8080/policy/policies/facis/guard/1.0/evaluation.
	EvaluationURL string `json:"evaluation_url"`
	// TimeoutMS bounds one evaluation; it must stay under the guard's 1 s policy bound so that a slow
	// TSA is answered here, as POL-PDP-UNAVAILABLE, and logged.
	TimeoutMS int `json:"timeout_ms"`
}

// TSA is the IF-05 adapter over the TSA: the same /decision interface as Policy, the decision taken
// by the Rego bundle the TSA has active.
type TSA struct {
	url     string
	timeout time.Duration
	http    *http.Client
	callers *meshcaller.XFCC
	log     *slog.Logger
}

func NewTSA(cfg TSAConfig, guardCallers []string, log *slog.Logger) (*TSA, error) {
	if cfg.EvaluationURL == "" || cfg.TimeoutMS < 1 || cfg.TimeoutMS >= 1000 || len(guardCallers) == 0 {
		return nil, errors.New("tsa configuration incomplete")
	}
	callers, err := meshcaller.NewXFCC(guardCallers)
	if err != nil {
		return nil, err
	}
	return &TSA{url: cfg.EvaluationURL, timeout: time.Duration(cfg.TimeoutMS) * time.Millisecond,
		http:    &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		callers: callers, log: log}, nil
}

// Decide asks the TSA. Any error, timeout or decision outside the IF-05 contract is an error, never
// a decision; a decision without its rule is refused too, since every decision must name it.
func (t *TSA) Decide(ctx context.Context, in hook.Input) (hook.Decision, error) {
	ctx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	input, err := json.Marshal(in)
	if err != nil {
		return hook.Decision{}, err
	}
	raw, err := tsabundle.EvaluateRaw(ctx, t.http, t.url, input)
	if err != nil {
		return hook.Decision{}, err
	}
	var d hook.Decision
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&d) != nil || dec.Decode(&struct{}{}) != io.EOF {
		return hook.Decision{}, errors.New("tsa decision is not an IF-05 decision")
	}
	if err := d.Validate(); err != nil {
		return hook.Decision{}, err
	}
	if d.RuleID == "" {
		return hook.Decision{}, errors.New("tsa decision names no rule")
	}
	return d, nil
}

func (t *TSA) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.URL.Path != "/decision" || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if _, err := t.callers.Authenticate(r); err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	var in hook.Input
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024))
	dec.DisallowUnknownFields()
	if dec.Decode(&in) != nil || dec.Decode(&struct{}{}) != io.EOF {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	d, err := t.Decide(r.Context(), in)
	if err != nil {
		t.log.Error("policy decision", "correlation_id", in.CorrelationID, "engine", "tsa", "reason_code", hook.ReasonPDPUnavailable, "error", err.Error())
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"reason_code":"` + hook.ReasonPDPUnavailable + `"}`))
		return
	}
	t.log.Info("policy decision", "correlation_id", in.CorrelationID, "engine", "tsa", "allow", d.Allow,
		"rule_id", d.RuleID, "bundle_revision", d.BundleRevision, "reason_code", d.ReasonCode)
	_ = json.NewEncoder(w).Encode(d)
}
