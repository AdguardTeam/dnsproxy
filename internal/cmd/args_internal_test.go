package cmd

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUsage_hostsFileEnabled(t *testing.T) {
	t.Parallel()

	b := &strings.Builder{}
	usage("dnsproxy", b)

	text := b.String()
	assert.Contains(t, text, "--hosts-file-enabled")
	assert.Contains(t, text, "Enabled by default")
	assert.Contains(t, text, "set to false to disable")
	assert.NotContains(t, text, "If specified, use hosts files")
}
