// +build aix darwin dragonfly linux netbsd openbsd solaris freebsd

package proxyutil

import "os"

// HaveAdminRights checks if the current user has root (administrator) rights
func HaveAdminRights() (bool, error) {
	return os.Getuid() == 0, nil
}
