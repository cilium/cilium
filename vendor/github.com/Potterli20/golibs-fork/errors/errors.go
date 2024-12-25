// Package errors is a drop-in replacement and extension of the Go standard
// library's package [errors].
package errors

import (
	stderrors "errors"
	"fmt"
	"strings"
)

// Error is the constant error type.
//
// See https://dave.cheney.net/2016/04/07/constant-errors.
type Error string

// Error implements the error interface for Error.
func (err Error) Error() (msg string) {
	return string(err)
}

// Wrapper is a copy of the hidden wrapper interface from the Go standard
// library.  It is added here for tests, linting, etc.
type Wrapper interface {
	Unwrap() error
}

// WrapperSlice is a copy of the hidden wrapper interface added to the Go standard
// library in Go 1.20.  It is added here for tests, linting, etc.
type WrapperSlice interface {
	Unwrap() []error
}

// Join returns an error that wraps the given errors.  Any nil error values are
// discarded.  Join returns nil if errs contains no non-nil values.  The error
// formats as the concatenation of the strings obtained by calling the Error
// method of each element of errs, with a newline between each string.
//
// It calls [errors.Join] from the Go standard library.
func Join(errs ...error) error {
	return stderrors.Join(errs...)
}

// As finds the first error in err's chain that matches target, and if so, sets
// target to that error value and returns true.  Otherwise, it returns false.
//
// It calls [errors.As] from the Go standard library.
func As(err error, target any) (ok bool) {
	return stderrors.As(err, target)
}

// Aser is a copy of the hidden aser interface from the Go standard library.  It
// is added here for tests, linting, etc.
type Aser interface {
	As(target any) (ok bool)
}

// Is reports whether any error in err's chain matches target.
//
// It calls [errors.Is] from the Go standard library.
func Is(err, target error) (ok bool) {
	return stderrors.Is(err, target)
}

// Iser is a copy of the hidden iser interface from the Go standard library.  It
// is added here for tests, linting, etc.
type Iser interface {
	Is(target error) (ok bool)
}

// New returns an error that formats as the given msg.  Each call to New returns
// a distinct error value even if the text is identical.
//
// It calls [errors.New] from the Go standard library.
//
// Deprecated: Use type [Error] and constant errors instead.
func New(msg string) (err error) {
	return stderrors.New(msg)
}

// Unwrap returns the result of calling the Unwrap method on err, if err's type
// contains an Unwrap method returning error.  Otherwise, Unwrap returns nil.
//
// It calls [errors.Unwrap] from the Go standard library.
func Unwrap(err error) (unwrapped error) {
	return stderrors.Unwrap(err)
}

// Deferred is the interface for errors that were returned by cleanup functions,
// such as Close.  This is useful in APIs which desire to handle such errors
// differently, for example to log them as warnings.
//
// Method Deferred returns a bool to mirror the behavior of types like
// [net.Error] and allow implementations to decide if the error is a deferred
// one dynamically.  Users of this API must check it's return value as well as
// the result [errors.As].
//
//	if derr := errors.Deferred(nil); errors.As(err, &derr) && derr.Deferred() {
//	        // …
//	}
//
// See https://dave.cheney.net/2014/12/24/inspecting-errors.
type Deferred interface {
	error
	Deferred() (ok bool)
}

// deferredError is a helper to implement Deferred.
type deferredError struct {
	error
}

// type check
var _ Deferred = deferredError{}

// Deferred implements the [Deferred] interface for deferredError.
func (err deferredError) Deferred() (ok bool) {
	return true
}

// type check
var _ error = deferredError{}

// Error implements the error interface for deferredError.
func (err deferredError) Error() (msg string) {
	return fmt.Sprintf("deferred: %s", err.error)
}

// Unwrap implements the [Wrapper] interface for deferredError.
func (err deferredError) Unwrap() (unwrapped error) {
	return err.error
}

// Pair is a pair of errors.  The Returned error is the main error that has been
// returned by a function.  The Deferred error is the error returned by the
// cleanup function, such as Close.
//
// In pairs returned from [WithDeferred], the Deferred error always implements
// the [Deferred] interface.
type Pair struct {
	Returned error
	Deferred error
}

// type check
var _ error = (*Pair)(nil)

// Error implements the error interface for *Pair.
func (err *Pair) Error() string {
	return fmt.Sprintf("returned: %q, deferred: %q", err.Returned, Unwrap(err.Deferred))
}

// type check
var _ Wrapper = (*Pair)(nil)

// Unwrap implements the [Wrapper] interface for *Pair.  It returns the
// Returned error.
func (err *Pair) Unwrap() (unwrapped error) {
	return err.Returned
}

// WithDeferred is a helper function for deferred errors.  For example, to
// preserve errors from the Close method, replace this:
//
//	defer f.Close()
//
// With this:
//
//	defer func() { err = errors.WithDeferred(err, f.Close()) }
//
// If returned is nil and deferred is non-nil, the returned error implements the
// [Deferred] interface.  If both returned and deferred are non-nil, result has
// the underlying type of [*Pair].
//
// # Warning
//
// This function requires that there be only ONE error named "err" in the
// function and that it is always the one that is returned.  Example (Bad)
// provides an example of the incorrect usage of WithDeferred.
func WithDeferred(returned, deferred error) (result error) {
	if deferred == nil {
		return returned
	}

	if returned == nil {
		return deferredError{error: deferred}
	}

	return &Pair{
		Returned: returned,
		Deferred: deferredError{error: deferred},
	}
}

// listError is an error containing several wrapped errors.
type listError struct {
	msg  string
	errs []error
}

// List wraps several errors into a single error with an additional message.
//
// TODO(a.garipov): Deprecate once golibs switches to Go 1.20.
func List(msg string, errs ...error) (err error) {
	return &listError{
		msg:  msg,
		errs: errs,
	}
}

// type check
var _ error = (*listError)(nil)

// Error implements the error interface for *listError.
func (err *listError) Error() (msg string) {
	switch l := len(err.errs); l {
	case 0:
		return err.msg
	case 1:
		return fmt.Sprintf("%s: %s", err.msg, err.errs[0])
	default:
		b := &strings.Builder{}

		// Here and further, ignore the errors since they are known to
		// be nil.
		_, _ = fmt.Fprintf(b, "%s: %d errors: ", err.msg, l)

		for i, e := range err.errs {
			if i == l-1 {
				_, _ = fmt.Fprintf(b, "%q", e)
			} else {
				_, _ = fmt.Fprintf(b, "%q, ", e)
			}
		}

		return b.String()
	}
}

// type check
var _ Wrapper = (*listError)(nil)

// Unwrap implements the Wrapper interface for *listError.
func (err *listError) Unwrap() (unwrapped error) {
	if len(err.errs) == 0 {
		return nil
	}

	return err.errs[0]
}

// Annotate annotates the error with the message, unless the error is nil.  The
// last verb in format must be a verb compatible with errors, for example "%w".
//
// # In Defers
//
// The primary use case for this function is to simplify code like this:
//
//	func (f *foo) doStuff(s string) (err error) {
//		defer func() {
//			if err != nil {
//				err = fmt.Errorf("bad foo %q: %w", s, err)
//			}
//		}()
//
//		// …
//	}
//
// Instead, write:
//
//	func (f *foo) doStuff(s string) (err error) {
//		defer func() { err = errors.Annotate(err, "bad foo %q: %w", s) }()
//
//		// …
//	}
//
// # At The End Of Functions
//
// Another possible use case is to simplify final checks like this:
//
//	func (f *foo) doStuff(s string) (err error) {
//		// …
//
//		if err != nil {
//			return fmt.Errorf("doing stuff with %s: %w", s, err)
//		}
//
//		return nil
//	}
//
// Instead, you could write:
//
//	func (f *foo) doStuff(s string) (err error) {
//		// …
//
//		return errors.Annotate(err, "doing stuff with %s: %w", s)
//	}
//
// # Warning
//
// This function requires that there be only ONE error named "err" in the
// function and that it is always the one that is returned.  Example (Bad)
// provides an example of the incorrect usage of WithDeferred.
func Annotate(err error, format string, args ...any) (annotated error) {
	if err == nil {
		return nil
	}

	return fmt.Errorf(format, append(args, err)...)
}
