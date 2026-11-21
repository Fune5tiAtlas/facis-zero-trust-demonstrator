package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
)

// maxTrustDoc bounds every trust document read: the issuer keys file, the pinned trust list and a
// TCR answer.
const maxTrustDoc = 1 << 20

// lister says whether TRAIN lists issuer as an active trust service. An error is "not known", and
// the issuer is not trusted until the next refresh says otherwise (fail closed).
type lister func(ctx context.Context, issuer string) (bool, error)

// trusted is the credential issuers a presentation may come from: those of keyed (the issuer keys
// file, if03.ParseIssuers' format) that listed reports. An issuer with keys but no listing, or
// whose listing cannot be read, is left out, so its credentials are CRED-ISSUER-UNTRUSTED.
func trusted(ctx context.Context, keyed if03.Issuers, listed lister) (if03.Issuers, []string) {
	out := if03.Issuers{}
	var dropped []string
	for iss, keys := range keyed {
		if ok, err := listed(ctx, iss); err != nil || !ok {
			dropped = append(dropped, iss)
			continue
		}
		out[iss] = keys
	}
	return out, dropped
}

func readIssuers(path string) (if03.Issuers, error) {
	b, err := readBounded(path)
	if err != nil {
		return nil, err
	}
	return if03.ParseIssuers(b)
}

func readBounded(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	switch {
	case err != nil:
		return nil, errors.New("cannot read the file")
	case len(b) > maxTrustDoc:
		return nil, errors.New("the file is larger than 1 MiB")
	}
	return b, nil
}

// pinnedList is the FIXTURE trust source: a trust list in the JSON form TSPA serves at
// GET /tspa/v1/{framework}/trust-list (docs/tspa-publish-api.md), read from a file at every call.
// Unlike the TCR it verifies neither the trust-list VC's signature nor its hash, and it resolves no
// DNS: it stands in for TRAIN where no TCR is reachable and must never be a zone's trust source of
// record.
func pinnedList(path string) lister {
	return func(_ context.Context, issuer string) (bool, error) {
		b, err := readBounded(path)
		if err != nil {
			return false, err
		}
		var doc any
		if err := json.Unmarshal(b, &doc); err != nil {
			return false, errors.New("the trust list is not JSON")
		}
		return listsActive(doc, issuer), nil
	}
}

// tcrList asks the TRAIN Trusted Content Resolver (eclipse-xfsc/train-trust-validator,
// POST /tcr/v1/resolve, docs/tspa-publish-api.md section 4): the TCR walks the DNS chain from the
// pointer to the trust-list VC, checks the VC's signature and the list's hash, and returns the
// entries whose ServiceTypeIdentifier equals the issuer. The issuer is listed when one trust list
// with vcVerified true holds an active service for it and is inside its validity window.
//
// The window is required because vcVerified does not cover it: the documented TCR (train-trust-
// validator e27b1ed) checks the trust-list VC's signature and hash but never its expirationDate
// (docs/tspa-publish-api.md, section 1), so an expired signed list would still authorise. The
// service reads the window from the resolved trust list as the TCR answers it (expirationDate or
// validUntil, and validFrom or issuanceDate when present, RFC 3339) and fails closed when it is
// missing, unreadable, not begun or passed. The documented TCR returns no window, so against it
// every issuer is refused until the TCR returns the window of the VC it verified.
func tcrList(client *http.Client, base string, pointers []string, now func() time.Time) lister {
	endpoint := strings.TrimRight(base, "/") + "/tcr/v1/resolve"
	return func(ctx context.Context, issuer string) (bool, error) {
		body, _ := json.Marshal(map[string]any{"issuer": issuer, "trustSchemePointers": pointers})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return false, err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return false, errors.New("tcr unreachable")
		}
		defer func() { _ = resp.Body.Close() }()
		raw, err := io.ReadAll(io.LimitReader(resp.Body, maxTrustDoc+1))
		if err != nil || len(raw) > maxTrustDoc || resp.StatusCode != http.StatusOK {
			return false, errors.New("tcr answer refused")
		}
		var answer struct {
			ResolvedResults []struct {
				ResolvedDoc *struct {
					Endpoints []struct {
						TrustList      any    `json:"trustList"`
						VCVerified     bool   `json:"vcVerified"`
						ExpirationDate string `json:"expirationDate"`
						ValidUntil     string `json:"validUntil"`
						ValidFrom      string `json:"validFrom"`
						IssuanceDate   string `json:"issuanceDate"`
					} `json:"endpoints"`
				} `json:"resolvedDoc"`
			} `json:"resolvedResults"`
		}
		if json.Unmarshal(raw, &answer) != nil {
			return false, errors.New("tcr answer is not JSON")
		}
		var outside error
		for _, r := range answer.ResolvedResults {
			if r.ResolvedDoc == nil {
				continue
			}
			for _, e := range r.ResolvedDoc.Endpoints {
				if !e.VCVerified || !listsActive(e.TrustList, issuer) {
					continue
				}
				if err := within(now(), first(e.ExpirationDate, e.ValidUntil), first(e.ValidFrom, e.IssuanceDate)); err != nil {
					outside = err
					continue
				}
				return true, nil
			}
		}
		return false, outside
	}
}

func first(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// within says whether now lies in [from, until]; until is required, from optional.
func within(now time.Time, until, from string) error {
	if until == "" {
		return errors.New("trust list has no validity end")
	}
	end, err := time.Parse(time.RFC3339, until)
	if err != nil {
		return errors.New("trust list validity end unreadable")
	}
	if !now.Before(end) {
		return errors.New("trust list expired")
	}
	if from != "" {
		start, err := time.Parse(time.RFC3339, from)
		if err != nil || now.Before(start) {
			return errors.New("trust list not yet valid")
		}
	}
	return nil
}

// listsActive finds, anywhere in a trust list, a service object whose ServiceTypeIdentifier is
// issuer (the TCR's lookup key) and whose ServiceCurrentStatus is "active". The search does not
// depend on the wrapper members around the entries, which differ between TSPA's raw list and the
// TCR's answer.
func listsActive(doc any, issuer string) bool {
	switch v := doc.(type) {
	case map[string]any:
		if v["ServiceTypeIdentifier"] == issuer && v["ServiceCurrentStatus"] == "active" {
			return true
		}
		for _, child := range v {
			if listsActive(child, issuer) {
				return true
			}
		}
	case []any:
		for _, child := range v {
			if listsActive(child, issuer) {
				return true
			}
		}
	}
	return false
}
