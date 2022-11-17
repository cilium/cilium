package features

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

// wrapProbeErrors wraps err to prevent callers from directly comparing
// it to exported sentinels. Error rewriting in Go can be implemented by
// deferring a closure over a named error return variable. This gives the
// closure access to the stack space where the return value will be written,
// allowing it to intercept and rewrite all returns, regardless of whether
// or not the return statements use the named return variable.
//
//	func foo() (err error) {
//	  defer func() {
//	    err = wrapProbeErrors(err)
//	  }
//	  return errors.New("this error will be wrapped")
//	}
func wrapProbeErrors(err error) error {
	if err == nil {
		return nil
	}

	// Wrap all errors to prevent them from being compared directly
	// to exported sentinels by the caller.
	errStr := "%w"

	if !errors.Is(err, ebpf.ErrNotSupported) {
		// Wrap unexpected errors with an appropriate error string.
		errStr = "unexpected error during feature probe: %w"
	}

	return fmt.Errorf(errStr, err)
}
