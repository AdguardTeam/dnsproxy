package proxy

import "time"

// clock is the interface for provider of current time.  It's used to simplify
// testing.
//
// TODO(e.burkov):  Move to golibs.
type clock interface {
	// Now returns the current local time.
	Now() (now time.Time)
}

// type check
var _ clock = realClock{}

// realClock is the [clock] which actually uses the [time] package.
type realClock struct{}

// Now implements the [clock] interface for RealClock.
func (realClock) Now() (now time.Time) { return time.Now() }
