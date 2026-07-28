package upstream_test

import (
	"time"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// testTimeout is common timeout for tests.
const testTimeout = 1 * time.Second

// testLogger is common logger for tests.
var testLogger = slogutil.NewDiscardLogger()
