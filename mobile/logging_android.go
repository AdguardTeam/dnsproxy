package mobile

import (
	"fmt"
	"os"
	"syscall"
)

// redirectStderr redirects Stderr to stderrRedirectPath file.
// it's necessary to collect panic logs for Android app
func redirectStderr(stderrRedirectPath string) error {
	file, err := os.Create(stderrRedirectPath)
	if err != nil {
		return fmt.Errorf("cannot create file %s cause: %s", stderrRedirectPath, err)
	}

	if err := syscall.Dup3(int(file.Fd()), int(os.Stderr.Fd()), 0); err != nil {
		return fmt.Errorf("cannot redirect stderr to %s cause: %s", stderrRedirectPath, err)
	}
	return nil
}
