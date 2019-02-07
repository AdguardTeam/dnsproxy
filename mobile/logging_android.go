package mobile

/*
#cgo LDFLAGS: -landroid -llog
#include <android/log.h>
#include <stdlib.h>
#include <string.h>
*/
import "C"
import (
	"bufio"
	"os"
	"syscall"
	"unsafe"
)

var (
	ctag = C.CString("GoLog")
)

// configureStderr re-routes stderr to the specified adapter
// this is useful to capture panic output
func configureStderr(logWriter LogWriter) {
	r, w, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	if err := syscall.Dup3(int(w.Fd()), int(os.Stderr.Fd()), 0); err != nil {
		panic(err)
	}
	go lineLog(r, C.ANDROID_LOG_ERROR, logWriter)
}

// Most of the code here is from https://github.com/golang/mobile/blob/master/internal/mobileinit/mobileinit_android.go
func lineLog(f *os.File, priority C.int, logWriter LogWriter) {
	const logSize = 1024 // matches android/log.h.
	r := bufio.NewReaderSize(f, logSize)
	for {
		line, _, err := r.ReadLine()
		str := string(line)
		if err != nil {
			str += " " + err.Error()
		}
		cstr := C.CString(str)
		C.__android_log_write(priority, ctag, cstr)
		C.free(unsafe.Pointer(cstr))

		// If there is a custom logWriter, pass the string to it
		logWriter.Write("STDERR: " + str)
		if err != nil {
			break
		}
	}
}
