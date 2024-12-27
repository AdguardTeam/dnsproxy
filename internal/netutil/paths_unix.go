//go:build unix

package netutil

import "github.com/AdguardTeam/golibs/hostsfile"

// defaultHostsPaths returns default paths to hosts files for UNIX.
func defaultHostsPaths() (paths []string, err error) {
	paths, err = hostsfile.DefaultHostsPaths()
	if err != nil {
		// Should not happen because error is always nil.
		panic(err)
	}

	res := make([]string, 0, len(paths))
	for _, p := range paths {
		res = append(res, "/"+p)
	}

	return res, nil
}
