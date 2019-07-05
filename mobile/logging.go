package mobile

import (
	"fmt"
	"strings"

	"github.com/AdguardTeam/golibs/log"
)

// LogWriter interface should be implemented inside project that will use dnsproxy mobile API to write dnsproxy log into mobile log
type LogWriter interface {
	Write(s string)
}

// LogWriterAdapter between go log and LogWriter
type LogWriterAdapter struct {
	lw LogWriter
}

func (w *LogWriterAdapter) Write(p []byte) (n int, err error) {
	line := strings.TrimSpace(string(p))
	w.lw.Write(line)
	return len(p), nil
}

// ConfigureLogger function is called from mobile API to write dnsproxy log into mobile log
// You need to create object that implements LogWriter interface and set it as argument of this function
func ConfigureLogger(verbose bool, stderrRedirectPath string, w LogWriter) error {
	SetLogLevel(verbose)
	if w != nil {
		adapter := &LogWriterAdapter{lw: w}
		log.SetOutput(adapter)
	}

	if stderrRedirectPath != "" {
		err := redirectStderr(stderrRedirectPath)
		if err != nil {
			return fmt.Errorf("cannot redirect stderr to %s cause: %s", stderrRedirectPath, err)
		}
	}

	return nil
}

// SetLogLevel function is called from mobile API and changes log level without LogWriter and srderrRedirect reconfiguration
func SetLogLevel(verbose bool) {
	if (log.GetLevel() == log.DEBUG && verbose) || (log.GetLevel() == log.INFO && !verbose) {
		return
	}

	if verbose {
		log.SetLevel(log.DEBUG)
	} else {
		log.SetLevel(log.INFO)
	}
}
