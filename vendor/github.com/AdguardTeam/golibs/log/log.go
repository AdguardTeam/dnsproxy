// Package log contains necessary logging functions
package log

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Level is the log level type.
type Level uint32

// Level constants.
const (
	ERROR Level = iota
	INFO
	DEBUG
)

// String implements fmt.Stringer for Level
func (l Level) String() string {
	switch l {
	case DEBUG:
		return "debug"
	case INFO:
		return "info"
	case ERROR:
		return "error"
	default:
		panic(fmt.Sprintf("not a valid Level: %d", l))
	}
}

// level is the current logging level.  It must only be updated atomically.
var level = uint32(INFO)

// Timer is a wrapper for time
type Timer struct {
	start time.Time
}

// StartTimer returns a Timer with a start time
func StartTimer() Timer {
	return Timer{start: time.Now()}
}

// LogElapsed writes to log message and elapsed time
func (t *Timer) LogElapsed(message string, args ...any) {
	var buf strings.Builder
	buf.WriteString(message)
	buf.WriteString(fmt.Sprintf("; Elapsed time: %dms", int(time.Since(t.start)/time.Millisecond)))

	pc := make([]uintptr, 10)
	runtime.Callers(2, pc)
	f := runtime.FuncForPC(pc[0])

	levelStr := "info"
	if atomic.LoadUint32(&level) >= uint32(DEBUG) {
		levelStr = "debug"
	}
	writeLog(levelStr, f.Name(), buf.String(), args...)
}

// Writer returns the output destination for the default logger.
func Writer() io.Writer {
	return log.Writer()
}

// SetLevel sets logging level.
func SetLevel(l Level) {
	atomic.SwapUint32(&level, uint32(l))
}

// GetLevel returns level
func GetLevel() (l Level) {
	return Level(atomic.LoadUint32(&level))
}

// These constants are the same as in the standard package "log".
//
// See the output of:
//
//	go doc log.Ldate
const (
	Ldate = 1 << iota
	Ltime
	Lmicroseconds
	Llongfile
	Lshortfile
	LUTC
	Lmsgprefix
	LstdFlags = Ldate | Ltime
)

// SetOutput sets output printing method
func SetOutput(w io.Writer) {
	log.SetOutput(w)
}

// SetFlags sets the output flags for the default logger.  The flag bits are
// Ldate, Ltime, and so on.
func SetFlags(flags int) {
	log.SetFlags(flags)
}

// Fatal writes to error log and exits application
func Fatal(args ...any) {
	writeLog("fatal", "", "%s", fmt.Sprint(args...))
	os.Exit(1)
}

// Fatalf writes to error log and exits application
func Fatalf(format string, args ...any) {
	writeLog("fatal", "", format, args...)
	os.Exit(1)
}

// Error writes to error log
func Error(format string, args ...any) {
	writeLog("error", "", format, args...)
}

// Print writes to info log
func Print(args ...any) {
	Info("%s", fmt.Sprint(args...))
}

// Printf writes to info log
func Printf(format string, args ...any) {
	Info(format, args...)
}

// Println writes to info log
func Println(args ...any) {
	Info("%s", fmt.Sprint(args...))
}

// Info writes to info log
func Info(format string, args ...any) {
	if atomic.LoadUint32(&level) >= uint32(INFO) {
		writeLog("info", "", format, args...)
	}
}

// Debug writes to debug log
func Debug(format string, args ...any) {
	if atomic.LoadUint32(&level) >= uint32(DEBUG) {
		writeLog("debug", "", format, args...)
	}
}

// Tracef writes to debug log and adds the calling function's name
func Tracef(format string, args ...any) {
	if atomic.LoadUint32(&level) >= uint32(DEBUG) {
		writeLog("debug", getCallerName(), format, args...)
	}
}

// Get goroutine ID
// (https://blog.sgmansfield.com/2015/12/goroutine-ids/)
func goroutineID() uint64 {
	b := make([]byte, 64)
	b = b[:runtime.Stack(b, false)]
	b = bytes.TrimPrefix(b, []byte("goroutine "))
	b = b[:bytes.IndexByte(b, ' ')]
	n, _ := strconv.ParseUint(string(b), 10, 64)
	return n
}

// Construct a log message and write it
// TIME PID#GOID [LEVEL] FUNCNAME(): TEXT
func writeLog(levelStr string, funcName string, format string, args ...any) {
	var buf strings.Builder

	if atomic.LoadUint32(&level) >= uint32(DEBUG) {
		buf.WriteString(fmt.Sprintf("%d#%d ", os.Getpid(), goroutineID()))
	}

	buf.WriteString(fmt.Sprintf("[%s] ", levelStr))

	if len(funcName) != 0 {
		buf.WriteString(fmt.Sprintf("%s(): ", funcName))
	}

	buf.WriteString(fmt.Sprintf(format, args...))
	log.Println(buf.String())
}

// StdLog returns a Go standard library logger that writes everything to logs
// the way this library's logger would.  This is useful for cases that require
// a stdlib logger, for example http.Server.ErrorLog.
func StdLog(prefix string, l Level) (std *log.Logger) {
	slw := &stdLogWriter{
		prefix: prefix,
		level:  l,
	}

	return log.New(slw, "", 0)
}

type stdLogWriter struct {
	prefix string
	level  Level
}

func (w *stdLogWriter) Write(p []byte) (n int, err error) {
	if atomic.LoadUint32(&level) < uint32(w.level) {
		return 0, nil
	}

	// The log.(*Logger).Output() method always appends a new line symbol to
	// the message before calling Write.  We do the same thing, so trim it.
	p = bytes.TrimSuffix(p, []byte{'\n'})

	var logFunc func(format string, args ...any)
	switch w.level {
	case ERROR:
		logFunc = Error
	case DEBUG:
		logFunc = Debug
	case INFO:
		logFunc = Info
	}

	if prefix := w.prefix; prefix == "" {
		logFunc("%s", p)
	} else {
		logFunc("%s: %s", prefix, p)
	}

	return len(p), nil
}

// OnPanic is a convenient deferred helper function to log a panic in
// a goroutine.  It should not be used where proper error handling is required.
func OnPanic(prefix string) {
	if v := recover(); v != nil {
		if prefix != "" {
			Error("%s: recovered from panic: %v", prefix, v)
			debug.PrintStack()

			return
		}

		Error("recovered from panic: %v", v)
		debug.PrintStack()
	}
}

// OnPanicAndExit is a convenient deferred helper function to log a panic in
// a goroutine.  Once a panic happens, it logs it and then calls os.Exit with
// the specified exit code.
func OnPanicAndExit(prefix string, exitCode int) {
	if v := recover(); v != nil {
		if prefix != "" {
			Error("%s: panic encountered, exiting: %v", prefix, v)
			debug.PrintStack()

			os.Exit(exitCode)
			return
		}

		Error("panic encountered, exiting: %v", v)
		debug.PrintStack()
		os.Exit(exitCode)
	}
}

// OnCloserError is a convenient helper to log errors returned by io.Closer
// The point is to not lose information from deferred Close calls. The error is
// logged with the specified logging level.
//
// Instead of:
//
//	defer f.Close()
//
// You can now write:
//
//	defer log.OnCloserError(f, log.DEBUG)
//
// Note that if closer is nil, it is simply ignored.
func OnCloserError(closer io.Closer, l Level) {
	if closer == nil {
		return
	}

	err := closer.Close()
	if err == nil {
		return
	}

	if atomic.LoadUint32(&level) >= uint32(l) {
		format := "error occurred in a Close call: %v"
		writeLog(l.String(), getCallerName(), format, err)
	}
}

// getCallerName tries to get the caller name.
// Returns empty string if it fails.
func getCallerName() string {
	pc := make([]uintptr, 10)

	// This method is supposed to be used only from other log package
	// so it skips three calls.
	runtime.Callers(3, pc)
	if len(pc) > 0 {
		f := runtime.FuncForPC(pc[0])
		return f.Name()
	}
	return ""
}
