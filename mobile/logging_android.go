package mobile

import (
	"os"
	"syscall"
)

// redirectStderr redirects Stderr to stderrOutput file.
// it's necessary to collect panic logs for Android app
func redirectStderr(stderrOutput string) {
	if stderrOutput == "" {
		panic("no stderr redirect file was configured")
	}

	file, err := os.OpenFile(stderrOutput, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0755)
	if err != nil {
		panic(err)
	}
	if err := syscall.Dup3(int(file.Fd()), int(os.Stderr.Fd()), 0); err != nil {
		panic(err)
	}
}
