package acquire

import (
	"context"
	"errors"
	"regexp"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/transit"
)

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// SweepOrphans deletes the KV values under KVPrefix whose token_id has no upstream_token row and
// that were created more than OrphanAge ago, longer than any activation transaction can stay open
// (D10). A value with a row, in any state, is never touched here. It returns how many it deleted.
func (a *Acquirer) SweepOrphans(ctx context.Context) (int, error) {
	names, err := a.Secrets.List(ctx, a.kvPrefix())
	if err != nil {
		return 0, err
	}
	deleted := 0
	for _, id := range names {
		if !uuidPattern.MatchString(id) {
			continue // a sub-folder or a name that is not ours
		}
		var exists bool
		if err := a.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM upstream_token WHERE token_id = $1)`, id).Scan(&exists); err != nil {
			return deleted, err
		}
		if exists {
			continue
		}
		path := a.kvPrefix() + "/" + id
		created, err := a.Secrets.CreatedTime(ctx, path)
		if errors.Is(err, transit.ErrNotFound) {
			continue
		}
		if err != nil {
			return deleted, err
		}
		if a.now().Sub(created) <= OrphanAge {
			continue
		}
		if err := a.Secrets.Delete(ctx, path); err != nil {
			return deleted, err
		}
		deleted++
		if _, err := a.DB.Exec(ctx, auditSQL, "upstream.orphan_deleted", nil, nil, nil, id, CodeOrphan, nil); err != nil {
			a.log().ErrorContext(ctx, "audit row not written", "token_id", id, "reason_code", CodeOrphan)
		}
		a.log().InfoContext(ctx, "orphaned upstream token value deleted", "token_id", id)
	}
	return deleted, nil
}
