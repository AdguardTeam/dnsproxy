//go:build !darwin

package proxy_test

import "testing"

// skipDarwin is a helper that skips tests on macOS systems if their name
// contains the target substring.
//
// TODO(f.setrakov): Remove, when the other way to fix jiggle tests on macOS is
// found.
func skipDarwin(tb testing.TB, target string) {}
