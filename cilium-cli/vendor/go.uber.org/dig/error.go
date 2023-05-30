// Copyright (c) 2019 Uber Technologies, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package dig

import (
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"

	"go.uber.org/dig/internal/digreflect"
	"go.uber.org/dig/internal/dot"
)

// Error is an interface implemented by all Dig errors.
//
// Use this interface, in conjunction with [RootCause], in order to
// determine if errors you encounter come from Dig, or if they come
// from provided constructors or invoked functions. See [RootCause]
// for more info.
type Error interface {
	error

	// Writes the message or context for this error in the chain.
	//
	// Note: the Error interface must always have a private function
	// such as this one in order to maintain properly sealed.
	//
	// verb is either %v or %+v.
	writeMessage(w io.Writer, v string)
}

// a digError is a dig.Error with additional functionality for
// internal use - namely the ability to be formatted.
type digError interface {
	Error
	fmt.Formatter
}

// A PanicError occurs when a panic occurs while running functions given to the container
// with the [RecoverFromPanic] option being set. It contains the panic message from the
// original panic. A PanicError does not wrap other errors, and it does not implement
// dig.Error, meaning it will be returned from [RootCause]. With the [RecoverFromPanic]
// option set, a panic can be distinguished from dig errors and errors from provided/
// invoked/decorated functions like so:
//
//	rootCause := dig.RootCause(err)
//
//	var pe dig.PanicError
//	var de dig.Error
//	if errors.As(rootCause, &pe) {
//		// This is caused by a panic
//	} else if errors.As(err, &de) {
//		// This is a dig error
//	} else {
//		// This is an error from one of my provided/invoked functions or decorators
//	}
//
// Or, if only interested in distinguishing panics from errors:
//
//	var pe dig.PanicError
//	if errors.As(err, &pe) {
//		// This is caused by a panic
//	} else {
//		// This is an error
//	}
type PanicError struct {

	// The function the panic occurred at
	fn *digreflect.Func

	// The panic that was returned from recover()
	Panic any
}

// Format will format the PanicError, expanding the corresponding function if in +v mode.
func (e PanicError) Format(w fmt.State, c rune) {
	if w.Flag('+') && c == 'v' {
		fmt.Fprintf(w, "panic: %q in func: %+v", e.Panic, e.fn)
	} else {
		fmt.Fprintf(w, "panic: %q in func: %v", e.Panic, e.fn)
	}
}

func (e PanicError) Error() string {
	return fmt.Sprint(e)
}

// formatError will call a dig.Error's writeMessage() method to print the error message
// and then will automatically attempt to print errors wrapped underneath (which can create
// a recursive effect if the wrapped error's Format() method then points back to this function).
func formatError(e digError, w fmt.State, v rune) {
	multiline := w.Flag('+') && v == 'v'
	verb := "%v"
	if multiline {
		verb = "%+v"
	}

	// "context: " or "context:\n"
	e.writeMessage(w, verb)

	// Will route back to this function recursively if next error
	// is also wrapped and points back here
	wrappedError := errors.Unwrap(e)
	if wrappedError == nil {
		return
	}
	io.WriteString(w, ":")
	if multiline {
		io.WriteString(w, "\n")
	} else {
		io.WriteString(w, " ")
	}
	fmt.Fprintf(w, verb, wrappedError)
}

// RootCause returns the first non-dig.Error in a chain of wrapped
// errors, if there is one. Otherwise, RootCause returns the error
// on the bottom of the chain of wrapped errors.
//
// Use this function and errors.As to differentiate between Dig errors
// and errors thrown by provided constructors or invoked functions:
//
//	rootCause := dig.RootCause(err)
//	var de dig.Error
//	if errors.As(rootCause, &de) {
//	    // Is a Dig error
//	} else {
//	    // Is an error thrown by one of my provided/invoked/decorated functions
//	}
//
// See [PanicError] for an example showing how to additionally detect
// and handle panics in provided/invoked/decorated functions.
func RootCause(err error) error {
	var de Error
	// Dig down to first non dig.Error, or bottom of chain
	for ; errors.As(err, &de); err = errors.Unwrap(de) {
	}

	if err == nil {
		return de
	}

	return err
}

// errInvalidInput is returned whenever the user provides bad input when
// interacting with the container. May optionally have a more detailed
// error wrapped underneath.
type errInvalidInput struct {
	Message string
	Cause   error
}

var _ digError = errInvalidInput{}

// newErrInvalidInput creates a new errInvalidInput, wrapping the given
// other error that caused this error. If there is no underlying cause,
// pass in nil. This will cause all attempts to unwrap this error to return
// nil, replicating errors.Unwrap's behavior when passed an error without
// an Unwrap() method.
func newErrInvalidInput(msg string, cause error) errInvalidInput {
	return errInvalidInput{msg, cause}
}

func (e errInvalidInput) Error() string { return fmt.Sprint(e) }

func (e errInvalidInput) Unwrap() error { return e.Cause }

func (e errInvalidInput) writeMessage(w io.Writer, _ string) {
	fmt.Fprintf(w, e.Message)
}

func (e errInvalidInput) Format(w fmt.State, c rune) {
	formatError(e, w, c)
}

// errProvide is returned when a constructor could not be Provided into the
// container.
type errProvide struct {
	Func   *digreflect.Func
	Reason error
}

var _ digError = errProvide{}

func (e errProvide) Error() string { return fmt.Sprint(e) }

func (e errProvide) Unwrap() error { return e.Reason }

func (e errProvide) writeMessage(w io.Writer, verb string) {
	fmt.Fprintf(w, "cannot provide function "+verb, e.Func)
}

func (e errProvide) Format(w fmt.State, c rune) {
	formatError(e, w, c)
}

// errConstructorFailed is returned when a user-provided constructor failed
// with a non-nil error.
type errConstructorFailed struct {
	Func   *digreflect.Func
	Reason error
}

var _ digError = errConstructorFailed{}

func (e errConstructorFailed) Error() string { return fmt.Sprint(e) }

func (e errConstructorFailed) Unwrap() error { return e.Reason }

func (e errConstructorFailed) writeMessage(w io.Writer, verb string) {
	fmt.Fprintf(w, "received non-nil error from function "+verb, e.Func)
}

func (e errConstructorFailed) Format(w fmt.State, c rune) {
	formatError(e, w, c)
}

// errArgumentsFailed is returned when a function could not be run because one
// of its dependencies failed to build for any reason.
type errArgumentsFailed struct {
	Func   *digreflect.Func
	Reason error
}

var _ digError = errArgumentsFailed{}

func (e errArgumentsFailed) Error() string { return fmt.Sprint(e) }

func (e errArgumentsFailed) Unwrap() error { return e.Reason }

func (e errArgumentsFailed) writeMessage(w io.Writer, verb string) {
	fmt.Fprintf(w, "could not build arguments for function "+verb, e.Func)
}

func (e errArgumentsFailed) Format(w fmt.State, c rune) {
	formatError(e, w, c)
}

// errMissingDependencies is returned when the dependencies of a function are
// not available in the container.
type errMissingDependencies struct {
	Func   *digreflect.Func
	Reason error
}

var _ digError = errMissingDependencies{}

func (e errMissingDependencies) Error() string { return fmt.Sprint(e) }

func (e errMissingDependencies) Unwrap() error { return e.Reason }

func (e errMissingDependencies) writeMessage(w io.Writer, verb string) {
	fmt.Fprintf(w, "missing dependencies for function "+verb, e.Func)
}

func (e errMissingDependencies) Format(w fmt.State, c rune) {
	formatError(e, w, c)
}

// errParamSingleFailed is returned when a paramSingle could not be built.
type errParamSingleFailed struct {
	Key    key
	Reason error
	CtorID dot.CtorID
}

var _ digError = errParamSingleFailed{}

func (e errParamSingleFailed) Error() string { return fmt.Sprint(e) }

func (e errParamSingleFailed) Unwrap() error { return e.Reason }

func (e errParamSingleFailed) writeMessage(w io.Writer, _ string) {
	fmt.Fprintf(w, "failed to build %v", e.Key)
}

func (e errParamSingleFailed) Format(w fmt.State, c rune) {
	formatError(e, w, c)
}

func (e errParamSingleFailed) updateGraph(g *dot.Graph) {
	failed := &dot.Result{
		Node: &dot.Node{
			Name:  e.Key.name,
			Group: e.Key.group,
			Type:  e.Key.t,
		},
	}
	g.FailNodes([]*dot.Result{failed}, e.CtorID)
}

// errParamGroupFailed is returned when a value group cannot be built because
// any of the values in the group failed to build.
type errParamGroupFailed struct {
	Key    key
	Reason error
	CtorID dot.CtorID
}

var _ digError = errParamGroupFailed{}

func (e errParamGroupFailed) Error() string { return fmt.Sprint(e) }

func (e errParamGroupFailed) Unwrap() error { return e.Reason }

func (e errParamGroupFailed) writeMessage(w io.Writer, _ string) {
	fmt.Fprintf(w, "could not build value group %v", e.Key)
}

func (e errParamGroupFailed) Format(w fmt.State, c rune) {
	formatError(e, w, c)
}

func (e errParamGroupFailed) updateGraph(g *dot.Graph) {
	g.FailGroupNodes(e.Key.group, e.Key.t, e.CtorID)
}

// missingType holds information about a type that was missing in the
// container.
type missingType struct {
	Key key // item that was missing

	// If non-empty, we will include suggestions for what the user may have
	// meant.
	suggestions []key
}

// Format prints a string representation of missingType.
//
// With %v, it prints a short representation ideal for an itemized list.
//
//	io.Writer
//	io.Writer: did you mean *bytes.Buffer?
//	io.Writer: did you mean *bytes.Buffer, or *os.File?
//
// With %+v, it prints a longer representation ideal for standalone output.
//
//	io.Writer: did you mean to Provide it?
//	io.Writer: did you mean to use *bytes.Buffer?
//	io.Writer: did you mean to use one of *bytes.Buffer, or *os.File?
func (mt missingType) Format(w fmt.State, v rune) {
	plusV := w.Flag('+') && v == 'v'

	fmt.Fprint(w, mt.Key)
	switch len(mt.suggestions) {
	case 0:
		if plusV {
			io.WriteString(w, " (did you mean to Provide it?)")
		}
	case 1:
		sug := mt.suggestions[0]
		if plusV {
			fmt.Fprintf(w, " (did you mean to use %v?)", sug)
		} else {
			fmt.Fprintf(w, " (did you mean %v?)", sug)
		}
	default:
		if plusV {
			io.WriteString(w, " (did you mean to use one of ")
		} else {
			io.WriteString(w, " (did you mean ")
		}

		lastIdx := len(mt.suggestions) - 1
		for i, sug := range mt.suggestions {
			if i > 0 {
				io.WriteString(w, ", ")
				if i == lastIdx {
					io.WriteString(w, "or ")
				}
			}
			fmt.Fprint(w, sug)
		}
		io.WriteString(w, "?)")
	}
}

// errMissingType is returned when one or more values that were expected in
// the container were not available.
//
// Multiple instances of this error may be merged together by appending them.
type errMissingTypes []missingType // inv: len > 0

var _ digError = errMissingTypes(nil)

func newErrMissingTypes(c containerStore, k key) errMissingTypes {
	// Possible types we will look for in the container. We will always look
	// for pointers to the requested type and some extras on a per-Kind basis.
	suggestions := []reflect.Type{reflect.PtrTo(k.t)}

	if k.t.Kind() == reflect.Ptr {
		// The user requested a pointer but maybe we have a value.
		suggestions = append(suggestions, k.t.Elem())
	}

	knownTypes := c.knownTypes()
	if k.t.Kind() == reflect.Interface {
		// Maybe we have an implementation of the interface.
		for _, t := range knownTypes {
			if t.Implements(k.t) {
				suggestions = append(suggestions, t)
			}
		}
	} else {
		// Maybe we have an interface that this type implements.
		for _, t := range knownTypes {
			if t.Kind() == reflect.Interface {
				if k.t.Implements(t) {
					suggestions = append(suggestions, t)
				}
			}
		}
	}

	// range through c.providers is non-deterministic. Let's sort the list of
	// suggestions.
	sort.Sort(byTypeName(suggestions))

	mt := missingType{Key: k}
	for _, t := range suggestions {
		if len(c.getValueProviders(k.name, t)) > 0 {
			k.t = t
			mt.suggestions = append(mt.suggestions, k)
		}
	}

	return errMissingTypes{mt}
}

func (e errMissingTypes) Error() string { return fmt.Sprint(e) }

func (e errMissingTypes) writeMessage(w io.Writer, v string) {

	multiline := v == "%+v"

	if len(e) == 1 {
		io.WriteString(w, "missing type:")
	} else {
		io.WriteString(w, "missing types:")
	}

	if !multiline {
		// With %v, we need a space between : since the error
		// won't be on a new line.
		io.WriteString(w, " ")
	}

	for i, mt := range e {
		if multiline {
			io.WriteString(w, "\n\t- ")
		} else if i > 0 {
			io.WriteString(w, "; ")
		}

		if multiline {
			fmt.Fprintf(w, "%+v", mt)
		} else {
			fmt.Fprintf(w, "%v", mt)
		}
	}
}

func (e errMissingTypes) Format(w fmt.State, c rune) {
	formatError(e, w, c)
}

func (e errMissingTypes) updateGraph(g *dot.Graph) {
	missing := make([]*dot.Result, len(e))

	for i, mt := range e {
		missing[i] = &dot.Result{
			Node: &dot.Node{
				Name:  mt.Key.name,
				Group: mt.Key.group,
				Type:  mt.Key.t,
			},
		}
	}
	g.AddMissingNodes(missing)
}

type errVisualizer interface {
	updateGraph(*dot.Graph)
}
