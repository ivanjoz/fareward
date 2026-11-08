package fareward

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"
)

// The grants push: the backend sends each user's status and grant blobs, and the daemon keeps them
// in its own store instead of reading the backend's users table (fareward plan D7). Opcode 0x0A;
// mirrored by src/store/grants.rs.
//
//	[count:u16] then count × [company:i32][user:i32][flags:u8][status:i8]
//	                          [grants_len:u16][grants][sub_len:u16][sub_grants]
//
// The daemon stores a frame atomically, drops those users' cached grants, and only then answers.

const (
	opcodePutGrants = byte(0x0A)
	// grantsMaxPayload mirrors GRANTS_MAX_PAYLOAD_SIZE: PutUserGrants splits a push to fit it.
	grantsMaxPayload = 8 * 1024
	grantFlagDeleted = byte(0x01)
	grantsWait       = 10 * time.Second
)

// UserGrants is all the daemon needs to know about a user: the grant blobs as
// core.EncodeAccesosGrants writes them (users.accesos_computed and accesos_sub_computed) and the
// status. Deleted sends a user that no longer exists, which the daemon forgets.
type UserGrants struct {
	CompanyID int32
	UserID    int32
	Status    int8
	Grants    []byte
	SubGrants []byte
	Deleted   bool
}

// PutUserGrants pushes users' grants, in as many frames as it takes. Each frame is applied whole
// or not at all; an error means some frames may already be stored, so the caller retries the
// whole push — storing a user twice is harmless.
func PutUserGrants(ctx context.Context, users []UserGrants) error {
	client := farewardClient()
	if client == nil {
		return ErrCreditLimiterMissing
	}
	for start := 0; start < len(users); {
		payload, next, err := encodeGrantBatch(users, start)
		if err != nil {
			return err
		}
		reply, err := client.requestOnce(ctx, opcodePutGrants, payload, grantsWait)
		if err != nil {
			return err
		}
		if reply.shape != replyAck {
			return fmt.Errorf("%w: grants push answered with shape 0x%02X",
				ErrFarewardUnavailable, reply.shape)
		}
		start = next
	}
	return nil
}

// encodeGrantBatch encodes users from start on, as many as fit one frame, and returns where the
// next frame starts.
func encodeGrantBatch(users []UserGrants, start int) ([]byte, int, error) {
	payload := make([]byte, 2, grantsMaxPayload)
	count := 0
	index := start
	for ; index < len(users) && count < 0xFFFF; index++ {
		user := &users[index]
		if user.CompanyID <= 0 || user.UserID <= 0 {
			return nil, 0, fmt.Errorf("grants for company %d user %d: ids must be positive",
				user.CompanyID, user.UserID)
		}
		grants, subGrants, flags, status := user.Grants, user.SubGrants, byte(0), user.Status
		if user.Deleted {
			// A deleted user carries nothing but its ids: the daemon only removes the row.
			grants, subGrants, flags, status = nil, nil, grantFlagDeleted, 0
		}
		if len(grants) > 0xFFFF || len(subGrants) > 0xFFFF {
			return nil, 0, fmt.Errorf("grants of company %d user %d exceed 64 KiB",
				user.CompanyID, user.UserID)
		}
		size := 4 + 4 + 1 + 1 + 2 + len(grants) + 2 + len(subGrants)
		if 2+size > grantsMaxPayload {
			return nil, 0, fmt.Errorf("grants of company %d user %d do not fit one frame (%d bytes)",
				user.CompanyID, user.UserID, size)
		}
		if len(payload)+size > grantsMaxPayload {
			break
		}
		payload = binary.BigEndian.AppendUint32(payload, uint32(user.CompanyID))
		payload = binary.BigEndian.AppendUint32(payload, uint32(user.UserID))
		payload = append(payload, flags, byte(status))
		payload = binary.BigEndian.AppendUint16(payload, uint16(len(grants)))
		payload = append(payload, grants...)
		payload = binary.BigEndian.AppendUint16(payload, uint16(len(subGrants)))
		payload = append(payload, subGrants...)
		count++
	}
	binary.BigEndian.PutUint16(payload[:2], uint16(count))
	return payload, index, nil
}
