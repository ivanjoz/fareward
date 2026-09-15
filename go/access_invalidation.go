package fareward

import (
	"context"
	"errors"
	"fmt"

	"github.com/ivanjoz/colbin"
)

// Opcode 0x06: drop a user's cached authorization grants.
//
//	[opcode:1][length:u16][payload][tag:8]
//
// The daemon caches `users.accesos_computed` for ten minutes so it can answer the route gate without
// reading ScyllaDB. This is what keeps that TTL a backstop rather than the mechanism: the backend
// sends it right after rewriting the column, so a revoked access stops working immediately instead
// of at the end of the window.
//
// Unanswered, like the request log, and for the same kind of reason — the TTL already bounds the
// damage if the frame is lost, so a user save must not wait on the daemon to acknowledge it. The
// payload layout is mirrored in fareward/src/limiter/access.rs.

// accessInvalidationFrame is the payload. Mirrored by `AccessInvalidation` in
// fareward/src/limiter/access.rs.
type accessInvalidationFrame struct {
	CompanyID int32 `cb:"1"`
	UserID    int32 `cb:"2"`
}

var accessInvalidationCodec = colbin.MustCodec[accessInvalidationFrame]()

// InvalidateAllCompanyUsers is the wildcard for the userID argument. User IDs start at 1, so zero is
// free to mean "every cached user of this company" — and colbin does not write a zero field, so the
// wildcard is literally the frame with no user in it.
const InvalidateAllCompanyUsers int32 = 0

var ErrAccessInvalidationNotConfigured = errors.New("fareward is not configured")

// InvalidateUserAccess tells the daemon to re-read one user's grants, or every user of a company.
//
// The error is worth logging and not worth failing a save over: the write that prompted this already
// succeeded, and the TTL is the fallback. A caller that treated this as fatal would roll back a
// correct user edit because a cache hint did not land.
func InvalidateUserAccess(ctx context.Context, companyID, userID int32) error {
	client := farewardClient()
	if client == nil {
		return ErrAccessInvalidationNotConfigured
	}
	payload, err := encodeAccessInvalidation(companyID, userID)
	if err != nil {
		return err
	}
	return client.send(ctx, opcodeInvalidateUserAccess, payload)
}

func encodeAccessInvalidation(companyID, userID int32) ([]byte, error) {
	if companyID <= 0 || companyID > 0xFF_FFFF {
		return nil, fmt.Errorf("company ID %d must fit positive uint24", companyID)
	}
	// Zero is the wildcard, so only the upper bound applies to the user.
	if userID < 0 || userID > 0xFF_FFFF {
		return nil, fmt.Errorf("user ID %d must fit uint24", userID)
	}
	return accessInvalidationCodec.Append(nil, &accessInvalidationFrame{
		CompanyID: companyID,
		UserID:    userID,
	}), nil
}
