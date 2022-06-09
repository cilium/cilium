package internal

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/cilium/ebpf/internal/unix"
)

// ErrorWithLog returns an error that includes logs from the
// kernel verifier.
//
// logErr should be the error returned by the syscall that generated
// the log. It is used to check for truncation of the output.
func ErrorWithLog(err error, log []byte, logErr error) error {
	// Convert verifier log C string by truncating it on the first 0 byte
	// and trimming trailing whitespace before interpreting as a Go string.
	if i := bytes.IndexByte(log, 0); i != -1 {
		log = log[:i]
	}
	logStr := string(bytes.Trim(log, "\t\r\n "))

	if errors.Is(logErr, unix.ENOSPC) {
		logStr += " (truncated...)"
	}

	return &VerifierError{err, logStr}
}

// VerifierError includes information from the eBPF verifier.
type VerifierError struct {
	cause error
	log   string
}

func (le *VerifierError) Unwrap() error {
	return le.cause
}

func (le *VerifierError) Error() string {
	if le.log == "" {
		return le.cause.Error()
	}

	return fmt.Sprintf("%s: %s", le.cause, le.log)
}
