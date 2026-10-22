// Package acquire obtains an upstream token from the peer zone's Connector and activates it (design D10).
package acquire

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/dpopproof"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/transit"
)

// Challenge is what the peer Connector issued for one grant.
type Challenge struct {
	Value     string
	ClientID  string
	Audience  string
	ExpiresAt time.Time
}

// OutcomeSource yields a fresh signed IF-03 outcome for a challenge: the verifier in a deployment, a
// fixture signer in tests. Each call returns a new outcome_id.
type OutcomeSource interface {
	Outcome(ctx context.Context, ch Challenge) (compactJWS string, err error)
}

// VPGrantType is the peer Connector's verified-presentation grant (IF-02 v1.1).
const VPGrantType = "urn:facis:params:oauth:grant-type:verified-presentation"

// KVPrefix is where upstream token values live in KV v2: KVPrefix + "/" + token_id, create-only.
const KVPrefix = "ztd/token-store/upstream"

// Timing of the activation transaction and its settlement (D10). The transaction cannot stay open
// longer than statementTimeout per statement and idleTimeout between them; reconciliation waits
// settleWait for it, longer than both; the orphan sweep leaves values younger than OrphanAge alone,
// longer than any of them.
const (
	statementTimeout = 5 * time.Second
	idleTimeout      = 10 * time.Second
	settleWait       = 30 * time.Second
	OrphanAge        = 10 * time.Minute
	maxBody          = 64 << 10
)

// Reason codes of acquisition, on audit rows and errors. The CRED-OUTCOME-* codes of IF-03 are
// used as they are, whether A's own check or the peer's refusal produced them.
const (
	CodeChallenge         = "ACQ-CHALLENGE-FAILED"    // no challenge from the peer
	CodeOutcomeSource     = "ACQ-OUTCOME-UNAVAILABLE" // the outcome source failed
	CodeStore             = "ACQ-STORE-UNAVAILABLE"   // A's database could not record the receipt
	CodePeerRefused       = "ACQ-PEER-REFUSED"        // the peer refused with another reason
	CodePeerLost          = "ACQ-PEER-RESPONSE-LOST"  // no readable answer: terminal for the outcome
	CodeTokenInvalid      = "ACQ-TOKEN-INVALID"       // the issued token failed A's checks
	CodeKVWrite           = "ACQ-KV-WRITE"            // the value could not be written
	CodeActivationRefused = "ACQ-ACTIVATION-REFUSED"  // the receipt was no longer consumable
	CodeActivationFailed  = "ACQ-ACTIVATION-FAILED"   // the transaction confirmed rolled back
	CodeCommitUnknown     = "ACQ-COMMIT-UNKNOWN"      // reconciliation could not settle it
	CodeOrphan            = "ACQ-ORPHAN-DELETED"      // the sweep removed a value without a row
)

// Error is a failed acquisition: a reason code and fixed text, never anything a peer sent.
type Error struct {
	Code string
	Err  error
}

func (e *Error) Error() string { return "acquire: " + e.Code + ": " + e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

func fail(code, text string) *Error { return &Error{Code: code, Err: errors.New(text)} }

// Route is one upstream route and how to acquire its token.
type Route struct {
	Name             string
	PeerZone         string
	Audience         string
	Tenant           string
	ConnectorURL     string // the peer Connector's base URL; /oauth2/challenge and /oauth2/token below it
	ClientID         string
	ClientSecretFile string // read per acquisition, never logged
	Outcomes         OutcomeSource
}

// Token is an activated upstream token: the committed active row, never the value.
type Token struct {
	ID        string
	ExpiresAt time.Time
}

// Acquirer acquires upstream tokens. Safe for concurrent use.
type Acquirer struct {
	DB         *pgxpool.Pool
	Signer     transit.Signer
	Secrets    transit.Secrets
	KeyName    string       // the store's transit key
	Trusted    if03.Issuers // IF-03 issuers A accepts: the peer's verifier keys
	HTTPClient *http.Client // nil: 10 s timeout; redirects are never followed
	Log        *slog.Logger
	Now        func() time.Time

	// commit settles the activation transaction; tests replace it to lose an acknowledgement.
	commit func(context.Context, pgx.Tx) error
	// prefix replaces KVPrefix in tests, so each test sweeps only its own values.
	prefix string
	// sweepPause runs in the sweep between the age check and the locked re-check; tests use it to
	// commit an activation there.
	sweepPause func(tokenID string)
}

func (a *Acquirer) kvPrefix() string {
	if a.prefix != "" {
		return a.prefix
	}
	return KVPrefix
}

// Acquire runs D10 for route: challenge from the peer, outcome, A's receipt, the grant with a
// transit-signed proof (one nonce retry), the response checks, the KV write, and one A transaction
// that consumes the receipt and activates the row. Every refusal and failure is audited and returned
// as *Error. A failure after the grant was sent is terminal for that outcome: the next call starts
// with a fresh challenge and outcome.
func (a *Acquirer) Acquire(ctx context.Context, r Route) (Token, error) {
	at := attempt{a: a, r: r, id: newUUID()}
	tok, err := at.run(ctx)
	if err != nil {
		var e *Error
		if !errors.As(err, &e) {
			e = &Error{Code: CodeStore, Err: err}
		}
		kind := "upstream.failed"
		if e.Code == CodeTokenInvalid || e.Code == CodePeerRefused || strings.HasPrefix(e.Code, "CRED-") {
			kind = "upstream.refused"
		}
		at.audit(ctx, kind, e.Code, at.tokenID)
		a.log().WarnContext(ctx, "upstream acquisition refused or failed", "route", r.Name, "attempt", at.id,
			"reason_code", e.Code, "outcome_id", at.outcomeID, "token_id", at.tokenID)
		return Token{}, e
	}
	a.log().InfoContext(ctx, "upstream token acquired", "route", r.Name, "attempt", at.id, "token_id", tok.ID,
		"outcome_id", at.outcomeID, "expires_at", tok.ExpiresAt)
	return tok, nil
}

type attempt struct {
	a         *Acquirer
	r         Route
	id        string // correlation_id of the attempt's audit rows
	outcomeID string
	tokenID   string
	detail    string // the failed response check, for the audit row
}

func (at *attempt) run(ctx context.Context) (Token, error) {
	a, r := at.a, at.r
	base, err := baseURL(r.ConnectorURL)
	if err != nil {
		return Token{}, fail(CodeChallenge, "connector URL is not an absolute http(s) URL")
	}
	secret, err := readSecret(r.ClientSecretFile)
	if err != nil {
		return Token{}, fail(CodeChallenge, "client secret unreadable")
	}
	if r.Outcomes == nil {
		return Token{}, fail(CodeOutcomeSource, "route has no outcome source")
	}
	key, err := LoadKey(ctx, a.DB, a.Signer, a.KeyName)
	if err != nil {
		return Token{}, fail(CodeStore, "store key unavailable")
	}

	// 1. Challenge from B.
	ch, err := at.challenge(ctx, base, secret)
	if err != nil {
		return Token{}, err
	}
	// 2. Outcome.
	jws, err := r.Outcomes.Outcome(ctx, ch)
	if err != nil {
		return Token{}, fail(CodeOutcomeSource, "outcome source failed")
	}
	// 3. A's own verification and receipt.
	o, err := if03.Verify(jws, a.Trusted, if03.Expect{ClientID: r.ClientID, Challenge: ch.Value, Audience: r.Audience}, a.now())
	if err != nil {
		var ie *if03.Error
		if errors.As(err, &ie) {
			return Token{}, &Error{Code: ie.Code, Err: errors.New("outcome refused by the store")}
		}
		return Token{}, fail(if03.CodeSignature, "outcome refused by the store")
	}
	at.outcomeID = o.OutcomeID
	if err := at.recordReceipt(ctx, o); err != nil {
		return Token{}, err
	}
	// 4. The grant at B. From here on, an unreadable answer is terminal for this outcome.
	token, err := at.grant(ctx, base, secret, key, jws, ch.Value)
	if err != nil {
		return Token{}, err
	}
	// 5. Response checks.
	claims, err := at.check(token, key.JKT())
	if err != nil {
		return Token{}, err
	}
	// 6. KV create-only.
	at.tokenID = newUUID()
	path := a.kvPrefix() + "/" + at.tokenID
	if err := a.Secrets.Create(ctx, path, []byte(token.AccessToken)); err != nil {
		// Nothing activated. A value that was written despite the error has no row and is swept.
		return Token{}, fail(CodeKVWrite, "upstream token value not written")
	}
	// 7. One A transaction.
	return at.activate(ctx, key, path, claims)
}

// challenge asks B for a challenge for the route's audience.
func (at *attempt) challenge(ctx context.Context, base, secret string) (Challenge, error) {
	status, _, body, err := at.post(ctx, base+"/oauth2/challenge", secret, url.Values{"audience": {at.r.Audience}}, "")
	if err != nil || status != http.StatusOK {
		return Challenge{}, fail(CodeChallenge, "peer issued no challenge")
	}
	var out struct {
		Challenge string `json:"challenge"`
		ExpiresIn int    `json:"expires_in"`
	}
	if json.Unmarshal(body, &out) != nil || !challengePattern.MatchString(out.Challenge) || out.ExpiresIn <= 0 {
		return Challenge{}, fail(CodeChallenge, "peer challenge malformed")
	}
	return Challenge{Value: out.Challenge, ClientID: at.r.ClientID, Audience: at.r.Audience,
		ExpiresAt: at.a.now().Add(time.Duration(out.ExpiresIn) * time.Second)}, nil
}

var challengePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,256}$`)

// recordReceipt inserts A's receipt, verified and unconsumed. An outcome A has seen before is never
// used again.
func (at *attempt) recordReceipt(ctx context.Context, o if03.Outcome) error {
	claims, _ := json.Marshal(o.Claims)
	var refs any
	if len(o.CredentialRefs) > 0 {
		refs, _ = json.Marshal(o.CredentialRefs)
	}
	tag, err := at.a.DB.Exec(ctx, `INSERT INTO verified_outcome
		(outcome_id, issuer, client_id, challenge, audience, status, claims, credential_refs, verified_at, expires_at, received_at)
		VALUES ($1, $2, $3, $4, $5, 'verified', $6, $7, $8, $9, $10) ON CONFLICT (outcome_id) DO NOTHING`,
		o.OutcomeID, o.Issuer, o.ClientID, o.Challenge, o.Audience, claims, refs, o.VerifiedAt, o.ExpiresAt, at.a.now())
	if err != nil {
		return fail(CodeStore, "receipt not recorded")
	}
	if tag.RowsAffected() == 0 {
		return fail(if03.CodeConsumed, "outcome already received")
	}
	return nil
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

// grant sends the verified-presentation grant with a fresh proof, retrying once with the server's
// nonce when challenged for one (a refusal before any write, so the outcome is still unused).
func (at *attempt) grant(ctx context.Context, base, secret string, key *Key, outcome, challenge string) (tokenResponse, error) {
	tokenURL := base + "/oauth2/token"
	form := url.Values{"grant_type": {VPGrantType}, "outcome": {outcome}, "challenge": {challenge}, "audience": {at.r.Audience}}
	nonce := ""
	for try := 0; ; try++ {
		proof, err := dpopproof.Build(ctx, key, dpopproof.Claims{HTM: http.MethodPost, HTU: tokenURL, Nonce: nonce})
		if err != nil {
			// Nothing was sent: the outcome is unused, but the attempt ends here all the same.
			return tokenResponse{}, fail(CodeStore, "proof not signed")
		}
		status, header, body, err := at.post(ctx, tokenURL, secret, form, proof)
		if err != nil || status >= 500 {
			return tokenResponse{}, fail(CodePeerLost, "no readable answer from the peer")
		}
		if status == http.StatusOK {
			var out tokenResponse
			if json.Unmarshal(body, &out) != nil || out.AccessToken == "" {
				return tokenResponse{}, fail(CodePeerLost, "no readable answer from the peer")
			}
			return out, nil
		}
		var refusal struct {
			Reason string `json:"reason"`
		}
		_ = json.Unmarshal(body, &refusal)
		if refusal.Reason == "dpop_use_nonce" && try == 0 && header.Get("DPoP-Nonce") != "" {
			nonce = header.Get("DPoP-Nonce")
			continue
		}
		if slices.Contains(credCodes, refusal.Reason) {
			return tokenResponse{}, &Error{Code: refusal.Reason, Err: errors.New("outcome refused by the peer")}
		}
		return tokenResponse{}, fail(CodePeerRefused, "grant refused by the peer")
	}
}

var credCodes = []string{if03.CodeSignature, if03.CodeNotVerified, if03.CodeMismatch, if03.CodeExpired, if03.CodeConsumed}

type issued struct {
	issuedAt, expiresAt time.Time
}

// check is A's acceptance of the issued token: DPoP-bound to the store key, for the route's
// audience, not expired. Only the payload is read; the signature is the peer's and its resources'.
func (at *attempt) check(t tokenResponse, jkt string) (issued, error) {
	bad := func(what string) (issued, error) {
		at.detail = what
		return issued{}, fail(CodeTokenInvalid, "issued token failed the "+what+" check")
	}
	if !strings.EqualFold(t.TokenType, "DPoP") {
		return bad("token_type")
	}
	parts := strings.Split(t.AccessToken, ".")
	if len(parts) != 3 {
		return bad("format")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return bad("format")
	}
	m, err := jose.ParseObject(raw)
	if err != nil {
		return bad("format")
	}
	cnf, err := jose.ParseObject(m["cnf"])
	if err != nil {
		return bad("cnf.jkt")
	}
	if got, _, ok := jose.String(cnf, "jkt"); !ok || got != jkt {
		return bad("cnf.jkt")
	}
	var auds []string
	if one, present, ok := jose.String(m, "aud"); present && ok {
		auds = []string{one}
	} else if json.Unmarshal(m["aud"], &auds) != nil {
		auds = nil
	}
	if !slices.Contains(auds, at.r.Audience) {
		return bad("aud")
	}
	exp, ok := numericDate(m["exp"])
	now := at.a.now()
	if !ok || !exp.After(now) {
		return bad("exp")
	}
	iat, ok := numericDate(m["iat"])
	if !ok || iat.After(exp) || iat.After(now.Add(time.Minute)) {
		iat = now
	}
	return issued{issuedAt: iat, expiresAt: exp}, nil
}

func numericDate(raw json.RawMessage) (time.Time, bool) {
	n, err := strconv.ParseInt(string(bytes.TrimSpace(raw)), 10, 64)
	if err != nil || n <= 0 {
		return time.Time{}, false
	}
	return time.Unix(n, 0), true
}

// activate is the A transaction: consume the receipt, insert the active row and its audit row,
// commit. The transaction first takes an advisory lock on token_id that it holds until it ends, so
// reconciliation can wait for it to settle.
func (at *attempt) activate(ctx context.Context, key *Key, path string, tok issued) (Token, error) {
	a := at.a
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return at.rolledBack(ctx, path, false)
	}
	if refused, err := at.stage(ctx, tx, key, path, tok); err != nil {
		// COMMIT was never sent: the transaction did not commit.
		_ = tx.Rollback(context.WithoutCancel(ctx))
		return at.rolledBack(ctx, path, refused)
	}
	commit := a.commit
	if commit == nil {
		commit = func(ctx context.Context, tx pgx.Tx) error { return tx.Commit(ctx) }
	}
	err = commit(ctx, tx)
	switch {
	case err == nil:
		return Token{ID: at.tokenID, ExpiresAt: tok.expiresAt}, nil
	case errors.Is(err, pgx.ErrTxCommitRollback):
		// The server answered COMMIT with ROLLBACK: the transaction had failed before it.
		return at.rolledBack(ctx, path, false)
	default:
		// Any other answer, a server error included, does not prove a rollback: a FATAL
		// termination can arrive after the commit took effect. The row decides, once the
		// transaction has settled; a COMMIT refused with an error leaves no row and lands there too.
		return at.reconcile(ctx, path, tok)
	}
}

func (at *attempt) stage(ctx context.Context, tx pgx.Tx, key *Key, path string, tok issued) (refused bool, err error) {
	now := at.a.now()
	renewAfter := tok.issuedAt.Add(tok.expiresAt.Sub(tok.issuedAt) * 3 / 4)
	if _, err := tx.Exec(ctx, `SELECT set_config('statement_timeout', $2, true),
		set_config('idle_in_transaction_session_timeout', $3, true), pg_advisory_xact_lock(hashtextextended($1::text, 0))`,
		at.tokenID, ms(statementTimeout), ms(idleTimeout)); err != nil {
		return false, err
	}
	tag, err := tx.Exec(ctx, `UPDATE verified_outcome SET consumed_at = $3
		WHERE outcome_id = $1 AND audience = $2 AND status = 'verified' AND consumed_at IS NULL AND expires_at > $3`,
		at.outcomeID, at.r.Audience, now)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() == 0 {
		return true, errors.New("receipt not consumable")
	}
	if _, err := tx.Exec(ctx, `INSERT INTO upstream_token
		(token_id, peer_zone, audience, tenant, outcome_id, token_ref, key_ref, state, issued_at, expires_at, renew_after)
		VALUES ($1, $2, $3, $4, $5, $6, $7, 'active', $8, $9, $10)`,
		at.tokenID, at.r.PeerZone, at.r.Audience, at.r.Tenant, at.outcomeID, path, key.Ref(), tok.issuedAt, tok.expiresAt, renewAfter); err != nil {
		return false, err
	}
	_, err = tx.Exec(ctx, auditSQL, "upstream.acquired", at.id, at.r.ClientID, at.outcomeID, at.tokenID, nil, at.auditDetail())
	return false, err
}

// rolledBack handles a transaction confirmed not committed: the value is deleted.
func (at *attempt) rolledBack(ctx context.Context, path string, refused bool) (Token, error) {
	at.deleteValue(ctx, path)
	if refused {
		return Token{}, fail(CodeActivationRefused, "receipt not consumable")
	}
	return Token{}, fail(CodeActivationFailed, "activation rolled back")
}

// reconcile waits for the activation transaction to end (its advisory lock is free once it
// committed or aborted; the server's timeouts bound how long that takes), then reads the row by
// token_id. Only a missing row lets the value go; if the wait or the read fails, the value stays for
// the orphan sweep, which applies the same rule.
func (at *attempt) reconcile(ctx context.Context, path string, tok issued) (Token, error) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), settleWait+5*time.Second)
	defer cancel()
	deleted, err := at.a.deleteIfNoRow(rctx, at.tokenID, path)
	switch {
	case err != nil:
		return Token{}, fail(CodeCommitUnknown, "activation outcome unknown; value kept for the orphan sweep")
	case !deleted:
		return Token{ID: at.tokenID, ExpiresAt: tok.expiresAt}, nil
	default:
		return Token{}, fail(CodeActivationFailed, "activation did not commit")
	}
}

// deleteIfNoRow deletes the KV value at path only if token_id has no upstream_token row, deciding
// under the token's advisory lock, the one activation holds until it ends: the wait covers an
// activation still in flight, and the deletion happens before the lock is released, so no
// activation of that token_id can commit between the check and the deletion. READ COMMITTED is
// explicit and the lock and the check are separate statements, so the check reads a snapshot taken
// after the wait, whatever the database's default isolation is.
func (a *Acquirer) deleteIfNoRow(ctx context.Context, tokenID, path string) (deleted bool, err error) {
	tx, err := a.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout', $1, true)`, ms(settleWait)); err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))`, tokenID); err != nil {
		return false, err
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM upstream_token WHERE token_id = $1)`, tokenID).Scan(&exists); err != nil {
		return false, err
	}
	if exists {
		return false, nil
	}
	if err := a.Secrets.Delete(ctx, path); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

func ms(d time.Duration) string { return strconv.FormatInt(d.Milliseconds(), 10) }

func (at *attempt) deleteValue(ctx context.Context, path string) {
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := at.a.Secrets.Delete(dctx, path); err != nil {
		// Left for the orphan sweep: it has no row.
		at.a.log().WarnContext(ctx, "upstream token value not deleted; left for the orphan sweep", "token_id", at.tokenID)
	}
}

const auditSQL = `INSERT INTO audit_event (kind, correlation_id, client_id, outcome_id, token_id, reason_code, detail)
	VALUES ($1, $2, $3, $4, $5, $6, $7)`

func (at *attempt) auditDetail() []byte {
	d := map[string]string{"route": at.r.Name, "peer_zone": at.r.PeerZone, "audience": at.r.Audience}
	if at.detail != "" {
		d["check"] = at.detail
	}
	b, _ := json.Marshal(d)
	return b
}

// audit writes a refusal or failure row outside any transaction, best effort.
func (at *attempt) audit(ctx context.Context, kind, code, tokenID string) {
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if _, err := at.a.DB.Exec(actx, auditSQL, kind, at.id, at.r.ClientID, nullable(at.outcomeID), nullable(tokenID), code, at.auditDetail()); err != nil {
		at.a.log().ErrorContext(ctx, "audit row not written", "attempt", at.id, "reason_code", code)
	}
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// post sends a form with client_secret_basic (RFC 6749 2.3.1) and, when given, a DPoP proof.
func (at *attempt) post(ctx context.Context, target, secret string, form url.Values, proof string) (int, http.Header, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(url.QueryEscape(at.r.ClientID), url.QueryEscape(secret))
	if proof != "" {
		req.Header.Set("DPoP", proof)
	}
	resp, err := at.a.httpClient().Do(req)
	if err != nil {
		return 0, nil, nil, errors.New("request failed") // the transport's text is not ours to vouch for
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		return 0, nil, nil, errors.New("answer unreadable")
	}
	return resp.StatusCode, resp.Header, body, nil
}

func (a *Acquirer) httpClient() *http.Client {
	c := http.Client{Timeout: 10 * time.Second}
	if a.HTTPClient != nil {
		c = *a.HTTPClient
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}

func (a *Acquirer) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *Acquirer) log() *slog.Logger {
	if a.Log != nil {
		return a.Log
	}
	return slog.New(slog.DiscardHandler)
}

func baseURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", errors.New("bad URL")
	}
	return strings.TrimRight(u.String(), "/"), nil
}

func readSecret(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	s := strings.TrimRight(string(b), "\r\n")
	if s == "" {
		return "", errors.New("empty")
	}
	return s, nil
}
