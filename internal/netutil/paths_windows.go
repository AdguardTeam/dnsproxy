//go:build windows

package netutil

import (
	"fmt"
	"path"

	"golang.org/x/sys/windows"
)

// defaultHostsPaths returns default paths to hosts files for Windows.
func defaultHostsPaths() (paths []string, err error) {
	sysDir, err := windows.GetSystemDirectory()
	if err != nil {
		return []string{}, fmt.Errorf("getting system directory: %w", err)
	}

	p := path.Join(sysDir, "drivers", "etc", "hosts")

	return []string{p}, nil
}
