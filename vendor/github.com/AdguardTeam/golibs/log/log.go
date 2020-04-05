// Package log contains necessary logging functions
package log

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Logging level
const (
	ERROR = iota
	INFO  = iota
	DEBUG = iota
)

// Logging level
var logLevel = INFO

// Timer is a wrapper for time
type Timer struct {
	start time.Time
}

// StartTimer returns a Timer with a start time
func StartTimer() Timer {
	return Timer{start: time.Now()}
}

// LogElapsed writes to log message and elapsed time
func (t *Timer) LogElapsed(message string, args ...interface{}) {
	var buf strings.Builder
	buf.WriteString(message)
	buf.WriteString(fmt.Sprintf("; Elapsed time: %dms", int(time.Since(t.start)/time.Millisecond)))

	pc := make([]uintptr, 10)
	runtime.Callers(2, pc)
	f := runtime.FuncForPC(pc[0])

	level := "info"
	if logLevel >= DEBUG {
		level = "debug"
	}
	writeLog(level, f.Name(), buf.String(), args...)
}

// SetLevel sets logging level
func SetLevel(level int) {
	logLevel = level
}

// GetLevel returns logLevel
func GetLevel() int {
	return logLevel
}

// SetOutput sets output printing method
func SetOutput(w io.Writer) {
	log.SetOutput(w)
}

// Fatal writes to error log and exits application
func Fatal(args ...interface{}) {
	writeLog("fatal", "", "%s", fmt.Sprint(args...))
	os.Exit(1)
}

// Fatalf writes to error log and exits application
func Fatalf(format string, args ...interface{}) {
	writeLog("fatal", "", format, args...)
	os.Exit(1)
}

// Error writes to error log
func Error(format string, args ...interface{}) {
	writeLog("error", "", format, args...)
}

// Print writes to info log
func Print(args ...interface{}) {
	Info("%s", fmt.Sprint(args...))
}

// Printf writes to info log
func Printf(format string, args ...interface{}) {
	Info(format, args...)
}

// Println writes to info log
func Println(args ...interface{}) {
	Info("%s", fmt.Sprint(args...))
}

// Info writes to info log
func Info(format string, args ...interface{}) {
	if logLevel >= INFO {
		writeLog("info", "", format, args...)
	}
}

// Debug writes to debug log
func Debug(format string, args ...interface{}) {
	if logLevel >= DEBUG {
		writeLog("debug", "", format, args...)
	}
}

// Tracef writes to debug log and adds the calling function's name
func Tracef(format string, args ...interface{}) {
	if logLevel >= DEBUG {
		pc := make([]uintptr, 10)
		runtime.Callers(2, pc)
		f := runtime.FuncForPC(pc[0])
		writeLog("debug", f.Name(), format, args...)
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
func writeLog(level string, funcName string, format string, args ...interface{}) {
	var buf strings.Builder

	if logLevel >= DEBUG {
		buf.WriteString(fmt.Sprintf("%d#%d ", os.Getpid(), goroutineID()))
	}

	buf.WriteString(fmt.Sprintf("[%s] ", level))

	if len(funcName) != 0 {
		buf.WriteString(fmt.Sprintf("%s(): ", funcName))
	}

	buf.WriteString(fmt.Sprintf(format, args...))
	log.Println(buf.String())
}
