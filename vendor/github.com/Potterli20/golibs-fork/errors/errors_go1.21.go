//go:build go1.21

package errors

import stderrors "errors"

// TODO(a.garipov): Move to errors.go and add examples once golibs switches to
// Go 1.21.

// ErrUnsupported indicates that a requested operation cannot be performed,
// because it is unsupported.  For example, a call to os.Link when using a file
// system that does not support hard links.
//
// See [errors.ErrUnsupported].
var ErrUnsupported = stderrors.ErrUnsupported
