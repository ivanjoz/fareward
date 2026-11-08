package fareward

import (
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
)

// The CPU tariff: a base charge per request that covers the first free block, and one more credit
// per started block past it.
//
// The block past the base is configurable per kind of request ([rate_limit] get_block_kib and
// post_block_kib, through ConfigureTariff); the base charges and the free block are not. The
// backend charges with these numbers, and the route file it writes for the SPOE agent states them
// (Tariff), so the edge and the backend charge the same.
const (
	readBaseCredits  = 2
	writeBaseCredits = 5
	// freeBlockKiB is what the base charge covers, for every method.
	freeBlockKiB = 8

	// DefaultGetBlockKiB and DefaultPostBlockKiB are the blocks when the config sets none.
	DefaultGetBlockKiB  = 32
	DefaultPostBlockKiB = 8
	// maxBlockKiB is 1 GiB: a block larger than any response the backend serves is already free.
	maxBlockKiB = 1 << 20
)

var getBlockKiB, postBlockKiB atomic.Uint32

func init() {
	getBlockKiB.Store(DefaultGetBlockKiB)
	postBlockKiB.Store(DefaultPostBlockKiB)
}

// ConfigureTariff sets the size of the extra blocks, in KiB: getKiB for a GET's response, postKiB
// for a POST or PUT body. Zero keeps the default. Call it at startup, before the first charge and
// before the route file is written.
func ConfigureTariff(getKiB, postKiB int) error {
	for _, block := range []struct {
		name  string
		value int
	}{{"get_block_kib", getKiB}, {"post_block_kib", postKiB}} {
		if block.value < 0 || block.value > maxBlockKiB {
			return fmt.Errorf("%s must be between 1 and %d KiB (0 keeps the default), got %d",
				block.name, maxBlockKiB, block.value)
		}
	}
	if getKiB > 0 {
		getBlockKiB.Store(uint32(getKiB))
	}
	if postKiB > 0 {
		postBlockKiB.Store(uint32(postKiB))
	}
	return nil
}

// TariffStep is one method's tariff, in the shape the route file states it.
type TariffStep struct {
	Method      string
	BaseCredits uint16
	BaseKiB     int
	StepKiB     int
}

// Tariff is every charged method's tariff, as APICPUCredits applies it.
func Tariff() []TariffStep {
	write := int(postBlockKiB.Load())
	return []TariffStep{
		{"GET", readBaseCredits, freeBlockKiB, int(getBlockKiB.Load())},
		{"POST", writeBaseCredits, freeBlockKiB, write},
		{"PUT", writeBaseCredits, freeBlockKiB, write},
	}
}

// APICPUCredits applies the read/write base charge and rounds each partial extra block up.
//
// POST and PUT share one case, and that is the whole point: they are the same operation as far as
// this tariff is concerned — a body arrives and the handler writes — so the two must never be able
// to disagree about what they cost. Splitting them into separate cases is what let PUT fall through
// to the error branch and be silently free.
func APICPUCredits(method string, payloadBytes int) (uint16, error) {
	if payloadBytes < 0 {
		return 0, errors.New("payload size cannot be negative")
	}
	var baseCredits, blockKiB uint64
	switch strings.ToUpper(method) {
	case "GET":
		baseCredits, blockKiB = readBaseCredits, uint64(getBlockKiB.Load())
	case "POST", "PUT":
		baseCredits, blockKiB = writeBaseCredits, uint64(postBlockKiB.Load())
	default:
		return 0, fmt.Errorf("credit rate limiting does not support method %q", method)
	}
	extraBytes := uint64(0)
	if payloadBytes > freeBlockKiB*1024 {
		extraBytes = uint64(payloadBytes - freeBlockKiB*1024)
	}
	credits := baseCredits + ceilDivide(extraBytes, blockKiB*1024)
	if credits > uint64(^uint16(0)) {
		return 0, fmt.Errorf("calculated API credits %d exceed uint16", credits)
	}
	return uint16(credits), nil
}

// APICPUBaseCredits is what a request costs before its payload is measured.
//
// It exists because a GET is charged in two steps: the byte count only exists after the handler has
// run, but the authorization verdict is needed before it. The pre-handler frame therefore carries
// the base, and a top-up follows only when the response exceeded the free block.
func APICPUBaseCredits(method string) (uint16, error) {
	return APICPUCredits(method, 0)
}
