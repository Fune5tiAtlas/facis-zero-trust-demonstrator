package participant

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/connectorclient"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/dpopproof"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
)

// renewRetry is how long a session waits after a failed renewal before it tries the grant again; the
// current token is used meanwhile while it has not expired.
const renewRetry = 5 * time.Second

// ConnectorBootstrap is the token-mode Bootstrapper (design D12). The client is provisioned: its id
// and secret come from a mounted file, so the registering step is skipped and a run starts at
// presenting. A run asks the Connector for a challenge, has the OutcomeSource sign an IF-03 outcome
// for it, sends the verified-presentation grant with a DPoP proof of the Participant's own key and
// checks the token: DPoP-bound to that key, for the audience, not expired.
//
// The key is a P-256 key generated in the process when the bootstrap is built. A Participant is a
// workload, not the token store: it has no transit key, and its key never leaves the process.
type ConnectorBootstrap struct {
	client      connectorclient.Client // BaseURL and HTTP; the credentials are read per run
	credentials string
	audience    string
	outcomes    connectorclient.OutcomeSource
	key         processKey
	jkt         string

	grant sync.Mutex       // held across every grant: never two at once
	now   func() time.Time // test hook only
}

var _ Bootstrapper = (*ConnectorBootstrap)(nil)

// NewConnectorBootstrap validates the settings and generates the Participant's DPoP key. client nil
// means a 10 s timeout; redirects are never followed.
func NewConnectorBootstrap(connectorURL, credentialsFile, audience string, outcomes connectorclient.OutcomeSource, client *http.Client) (*ConnectorBootstrap, error) {
	base, err := connectorclient.BaseURL(connectorURL)
	if err != nil {
		return nil, errors.New("connector URL must be an absolute HTTP or HTTPS URL without credentials, query or fragment")
	}
	if credentialsFile == "" || strings.TrimSpace(audience) == "" || outcomes == nil {
		return nil, errors.New("credentials file, audience and outcome source are required")
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.New("DPoP key not generated")
	}
	key := processKey{k}
	jkt, err := key.JWK().Thumbprint()
	if err != nil {
		return nil, errors.New("DPoP key thumbprint")
	}
	b := &ConnectorBootstrap{
		client: connectorclient.Client{BaseURL: base, HTTP: client}, credentials: credentialsFile,
		audience: audience, outcomes: outcomes, key: key, jkt: jkt, now: time.Now,
	}
	b.client.Now = func() time.Time { return b.now() }
	return b, nil
}

// errBootstrap is all a failed run returns; the state and reason carry the detail.
var errBootstrap = errors.New("participant: token bootstrap failed")

// Run reports presenting, then acquiring_token, and returns a session holding the token; on failure it
// reports the failed_* state named by the step and the answer, and returns errBootstrap.
func (b *ConnectorBootstrap) Run(ctx context.Context, report func(State, string)) (TokenSession, error) {
	report(StatePresenting, TransitionStepStarted)
	id, secret, err := readCredentials(b.credentials)
	if err != nil {
		report(StateFailedRegister, TransitionBootstrapError)
		return nil, errBootstrap
	}
	client := b.client
	client.ClientID, client.ClientSecret = id, secret
	s := &connectorSession{b: b, client: &client}
	if err := s.acquire(ctx, report); err != nil {
		return nil, errBootstrap
	}
	return s, nil
}

type connectorSession struct {
	b      *ConnectorBootstrap
	client *connectorclient.Client

	mu      sync.Mutex
	token   string
	expires time.Time
	renewAt time.Time
	retryAt time.Time
}

// Authorize returns "DPoP <token>" and a fresh proof for method and target, signed by the Participant
// key, with ath bound to the token. When the token is due for renewal (three quarters of its lifetime)
// the grant is run again first, by one caller at a time; while that fails the current token is used
// until it expires, and the grant is tried again at most every renewRetry.
func (s *connectorSession) Authorize(ctx context.Context, method, target string) (string, string, error) {
	token, err := s.current(ctx)
	if err != nil {
		return "", "", err
	}
	proof, err := dpopproof.Build(ctx, s.b.key, dpopproof.Claims{HTM: method, HTU: target, ATH: connectorclient.ATH(token)})
	if err != nil {
		return "", "", errors.New("participant: proof not signed")
	}
	return "DPoP " + token, proof, nil
}

func (s *connectorSession) current(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.b.now()
	if now.Before(s.renewAt) || now.Before(s.retryAt) {
		if now.Before(s.expires) {
			return s.token, nil
		}
		return "", errors.New("participant: token expired; renewal failed")
	}
	if err := s.acquire(ctx, nil); err != nil {
		s.retryAt = now.Add(renewRetry)
		if now.Before(s.expires) {
			return s.token, nil
		}
		return "", errors.New("participant: token expired; renewal failed")
	}
	return s.token, nil
}

// acquire runs challenge, outcome, grant and checks under the bootstrap's grant lock and stores the
// token in s. report is nil for a renewal.
func (s *connectorSession) acquire(ctx context.Context, report func(State, string)) error {
	if report == nil {
		report = func(State, string) {}
	}
	b := s.b
	b.grant.Lock()
	defer b.grant.Unlock()

	ch, err := s.client.Challenge(ctx, b.audience)
	if err != nil {
		report(failure(err))
		return err
	}
	outcome, err := b.outcomes.Outcome(ctx, ch)
	if err != nil {
		report(StateFailedPresent, TransitionUpstreamError)
		return err
	}
	report(StateAcquiringToken, TransitionStepStarted)
	resp, err := s.client.Grant(ctx, b.key, outcome, ch.Value, b.audience)
	if err != nil {
		report(failure(err))
		return err
	}
	issued, err := s.client.Check(resp, b.jkt, b.audience)
	if err != nil {
		report(failure(err))
		return err
	}
	s.token, s.expires = resp.AccessToken, issued.ExpiresAt
	s.renewAt = issued.IssuedAt.Add(issued.ExpiresAt.Sub(issued.IssuedAt) * 3 / 4)
	s.retryAt = time.Time{}
	return nil
}

// failure is the state and reason for a Connector error. Unreachable (no answer, 5xx, lost grant
// answer) is the only failure the lifecycle retries; the next run uses a fresh challenge and outcome.
func failure(err error) (State, string) {
	var e *connectorclient.Error
	if !errors.As(err, &e) {
		return StateFailedToken, TransitionBootstrapError
	}
	switch {
	case e.Unreachable:
		return StateFailedConnector, TransitionConnectorUnreachable
	case e.Status == http.StatusUnauthorized:
		// invalid_client: the provisioned credentials are not (or no longer) registered.
		return StateFailedRegister, TransitionRegistrationRejected
	case e.Kind == connectorclient.KindChallenge && e.Status == 0:
		return StateFailedPresent, TransitionUpstreamError
	case e.Kind == connectorclient.KindChallenge:
		return StateFailedPresent, TransitionPresentationRejected
	case e.Kind == connectorclient.KindRefused && e.Reason == connectorclient.ReasonUseNonce:
		return StateFailedToken, TransitionNonceRetryExhausted
	case e.Kind == connectorclient.KindRefused && strings.HasPrefix(e.Reason, "CRED-"):
		return StateFailedPresent, TransitionPresentationRejected
	case e.Kind == connectorclient.KindRefused, e.Kind == connectorclient.KindTokenInvalid:
		return StateFailedToken, TransitionTokenRejected
	default:
		return StateFailedToken, TransitionBootstrapError
	}
}

const maxCredentialsBytes = 4 << 10

// readCredentials reads the mounted client credentials: one strict JSON object (jose.ParseObject: no
// duplicate member, nothing after it) with exactly the members client_id and client_secret, both
// non-empty strings. Errors never repeat the file's content.
func readCredentials(path string) (id, secret string, err error) {
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > maxCredentialsBytes {
		return "", "", errors.New("credentials unreadable")
	}
	m, err := jose.ParseObject(raw)
	if err != nil || len(m) != 2 {
		return "", "", errors.New("credentials malformed")
	}
	id, _, okID := jose.String(m, "client_id")
	secret, _, okSecret := jose.String(m, "client_secret")
	if !okID || !okSecret || id == "" || secret == "" {
		return "", "", errors.New("credentials malformed")
	}
	return id, secret, nil
}

// processKey is the Participant's DPoP key, held in the process.
type processKey struct{ k *ecdsa.PrivateKey }

func (p processKey) JWK() jose.JWK { return jose.PublicJWK(&p.k.PublicKey) }

func (p processKey) Sign(_ context.Context, in []byte) ([]byte, error) {
	digest := sha256.Sum256(in)
	r, s, err := ecdsa.Sign(rand.Reader, p.k, digest[:])
	if err != nil {
		return nil, err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return sig, nil
}
