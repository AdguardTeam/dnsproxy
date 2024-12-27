package netutil

// DefaultHostsPaths returns the slice of default paths to system hosts files.
//
// TODO(s.chzhen):  Since [fs.FS] is no longer needed, update the
// [hostsfile.DefaultHostsPaths] from golibs.
func DefaultHostsPaths() (paths []string, err error) {
	return defaultHostsPaths()
}
