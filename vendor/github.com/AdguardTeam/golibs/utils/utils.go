// Package utils provides simple helper functions that are used in AdGuard projects
package utils

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
)

var hostnameRegexp *regexp.Regexp
var hostnameRegexpLock sync.Mutex // to silence Go race detector

// IsValidHostname returns an error if hostname is invalid
func IsValidHostname(hostname string) error {
	hostnameRegexpLock.Lock()
	if hostnameRegexp == nil {
		re, err := compileHostnameRegexp()
		if err != nil {
			hostnameRegexpLock.Unlock()
			return fmt.Errorf("wrong regexp for hostname validation: %s", err)
		}
		hostnameRegexp = re
	}
	hostnameRegexpLock.Unlock()

	return matchHostname(hostnameRegexp, hostname)
}

// matchHostname matches regular expression against hostname and returns an error if there is no match
func matchHostname(re *regexp.Regexp, hostname string) error {
	parts := strings.Split(hostname, ".")
	for _, p := range parts {
		match := re.MatchString(p)
		if !match {
			return fmt.Errorf("wrong hostname specification: %s", hostname)
		}
	}

	return nil
}

// compileHostnameRegexp returns a Regexp object that can be used to match against hostname
func compileHostnameRegexp() (*regexp.Regexp, error) {
	return regexp.Compile("^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]*[a-zA-Z0-9])\\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\\-]*[A-Za-z0-9])$")
}
