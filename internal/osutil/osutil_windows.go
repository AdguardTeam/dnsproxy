//go:build windows

package osutil

import (
	"io/fs"
	"os"
	"path/filepath"

	"github.com/AdguardTeam/golibs/log"
	"golang.org/x/sys/windows"
)

func rootDirFS() (fsys fs.FS) {
	// TODO(a.garipov): Use a better way if golang/go#44279 is ever resolved.
	sysDir, err := windows.GetSystemDirectory()
	if err != nil {
		log.Error("aghos: getting root filesystem: %s; using C:", err)

		// Assume that C: is the safe default.
		return os.DirFS("C:")
	}

	return os.DirFS(filepath.VolumeName(sysDir))
}
