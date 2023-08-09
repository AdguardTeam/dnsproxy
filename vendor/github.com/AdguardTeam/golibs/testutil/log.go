package testutil

import (
	"io"
	"os"
	"testing"

	"github.com/AdguardTeam/golibs/log"
)

// DiscardLogOutput runs tests with discarded logger output.
//
// TODO(a.garipov): Refactor project that use this to not use a global logger.
func DiscardLogOutput(m *testing.M) {
	log.SetOutput(io.Discard)

	os.Exit(m.Run())
}
