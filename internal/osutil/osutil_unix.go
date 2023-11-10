//go:build !windows

package osutil

import (
	"io/fs"
	"os"
)

func rootDirFS() (fsys fs.FS) {
	return os.DirFS("/")
}
