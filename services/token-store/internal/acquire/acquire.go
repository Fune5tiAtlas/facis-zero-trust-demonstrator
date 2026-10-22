// Package acquire obtains an upstream token from the peer zone's Connector and activates it (design D10).
package acquire

import (
	"context"
	"time"
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
