// Useful functions

package utils

import (
	"fmt"
	"regexp"
	"strings"
)

var hostnameRegexp *regexp.Regexp

// IsValidHostname returns an error if hostname is invalid
func IsValidHostname(hostname string) error {
	if hostnameRegexp == nil {
		re, err := compileHostnameRegexp()
		if err != nil {
			return fmt.Errorf("wrong regexp for hostname validation: %s", err)
		}
		hostnameRegexp = re
	}

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
	return regexp.Compile("^([a-zA-Z0-9]+|[a-zA-Z0-9][a-zA-Z0-9-]*)+[a-zA-Z0-9]$")
}
