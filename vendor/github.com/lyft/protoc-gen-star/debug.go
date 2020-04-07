package pgs

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

// DebuggerCommon contains shared features of Debugger and Debugger-like types
// (such as BuildContext).
type DebuggerCommon interface {
	// Log writes v to the underlying logging location (typically, os.Stderr). It
	// uses the same behavior as log.Print, with all prefixes already attached.
	Log(v ...interface{})

	// Logf formats v and writes it to the underlying logging location
	// (typically, os.Stderr). It uses the same behavior as log.Printf, with all
	// prefixes already attached.
	Logf(format string, v ...interface{})

	// Debug behaves the same as Log, but only writes its output if debugging is
	// enabled for this Debugger.
	Debug(v ...interface{})

	// Debugf behaves the same as Logf, but only writes its output if debugging
	// is enabled for this Debugger.
	Debugf(format string, v ...interface{})

	// Fail behaves the same as Log, but also terminates the process. This method
	// should be used if an un-recoverable error is encountered.
	Fail(v ...interface{})

	// Failf behaves the same as Logf, but also terminates the process. This
	// method should be used if an un-recoverable error is encountered.
	Failf(format string, v ...interface{})

	// CheckErr ensures that err is nil. If err is not nil, Fail is called with
	// err and the provided v.
	CheckErr(err error, v ...interface{})

	// Assert ensures that expr evaluates to true. If expr is false, Fail is
	// called with the provided v.
	Assert(expr bool, v ...interface{})

	// Exit should terminate the current process with the provided code.
	Exit(code int)
}

// A Debugger provides utility methods to provide context-aware logging,
// error-checking, and assertions. The Debugger is used extensively within the
// protoc-gen-star generator, and is provided in a module's build context.
type Debugger interface {
	DebuggerCommon

	// Push returns a new Debugger with the provided prefix. When entering a new
	// context, this method should be used.
	Push(prefix string) Debugger

	// Pop returns the parent for the current Debugger. When exiting a context,
	// this method should be used.
	Pop() Debugger
}

type logger interface {
	Println(...interface{})
	Printf(string, ...interface{})
}

type errFunc func(err error, msgs ...interface{})

type failFunc func(msgs ...interface{})

type exitFunc func(code int)

type rootDebugger struct {
	err       errFunc
	fail      failFunc
	exit      exitFunc
	l         logger
	logDebugs bool
}

func initDebugger(d bool, l logger) Debugger {
	rd := rootDebugger{
		logDebugs: d,
		l:         l,
		exit:      os.Exit,
	}

	rd.fail = failFunc(rd.defaultFail)
	rd.err = errFunc(rd.defaultErr)

	return rd
}

func (d rootDebugger) defaultErr(err error, msg ...interface{}) {
	if err != nil {
		d.l.Printf("[error] %s: %v\n", fmt.Sprint(msg...), err)
		d.exit(1)
	}
}

func (d rootDebugger) defaultFail(msg ...interface{}) {
	d.l.Println(msg...)
	d.exit(1)
}

func (d rootDebugger) Log(v ...interface{})                  { d.l.Println(v...) }
func (d rootDebugger) Logf(format string, v ...interface{})  { d.l.Printf(format, v...) }
func (d rootDebugger) Fail(v ...interface{})                 { d.fail(fmt.Sprint(v...)) }
func (d rootDebugger) Failf(format string, v ...interface{}) { d.fail(fmt.Sprintf(format, v...)) }
func (d rootDebugger) Exit(code int)                         { d.exit(code) }

func (d rootDebugger) Debug(v ...interface{}) {
	if d.logDebugs {
		d.Log(v...)
	}
}

func (d rootDebugger) Debugf(format string, v ...interface{}) {
	if d.logDebugs {
		d.Logf(format, v...)
	}
}

func (d rootDebugger) CheckErr(err error, v ...interface{}) {
	if err != nil {
		d.err(err, fmt.Sprint(v...))
	}
}

func (d rootDebugger) Assert(expr bool, v ...interface{}) {
	if !expr {
		d.Fail(fmt.Sprint(v...))
	}
}

func (d rootDebugger) Push(prefix string) Debugger {
	return prefixedDebugger{
		parent: d,
		prefix: fmt.Sprintf("[%s]", prefix),
	}
}

func (d rootDebugger) Pop() Debugger {
	d.Fail("attempted to pop the root debugger")
	return nil
}

type prefixedDebugger struct {
	parent Debugger
	prefix string
}

func (d prefixedDebugger) prepend(v []interface{}) []interface{} {
	return append([]interface{}{d.prefix}, v...)
}

func (d prefixedDebugger) prependFormat(format string) string {
	if strings.HasPrefix(format, "[") {
		return d.prefix + format
	}

	return d.prefix + " " + format
}

func (d prefixedDebugger) Log(v ...interface{}) {
	d.parent.Log(d.prepend(v)...)
}

func (d prefixedDebugger) Logf(format string, v ...interface{}) {
	d.parent.Logf(d.prependFormat(format), v...)
}

func (d prefixedDebugger) Debug(v ...interface{}) {
	d.parent.Debug(d.prepend(v)...)
}

func (d prefixedDebugger) Debugf(format string, v ...interface{}) {
	d.parent.Debugf(d.prependFormat(format), v...)
}

func (d prefixedDebugger) Fail(v ...interface{}) {
	d.parent.Fail(d.prepend(v)...)
}

func (d prefixedDebugger) Failf(format string, v ...interface{}) {
	d.parent.Failf(d.prependFormat(format), v...)
}

func (d prefixedDebugger) CheckErr(err error, v ...interface{}) {
	d.parent.CheckErr(err, d.prepend(v)...)
}

func (d prefixedDebugger) Assert(expr bool, v ...interface{}) {
	d.parent.Assert(expr, d.prepend(v)...)
}

func (d prefixedDebugger) Exit(code int) { d.parent.Exit(code) }

func (d prefixedDebugger) Push(prefix string) Debugger {
	return prefixedDebugger{
		parent: d,
		prefix: "[" + prefix + "]",
	}
}

func (d prefixedDebugger) Pop() Debugger {
	return d.parent
}

// MockDebugger serves as a root Debugger instance for usage in tests. Unlike
// an actual Debugger, MockDebugger will not exit the program, but will track
// failures, checked errors, and exit codes.
type MockDebugger interface {
	Debugger

	// Output returns a reader of all logged data.
	Output() io.Reader

	// Failed returns true if Fail or Failf has been called on this debugger or a
	// descendant of it (via Push).
	Failed() bool

	// Err returns the error passed to CheckErr.
	Err() error

	// Exited returns true if this Debugger (or a descendant of it) would have
	// called os.Exit.
	Exited() bool

	// ExitCode returns the code this Debugger (or a descendant of it) passed to
	// os.Exit. If Exited() returns false, this value is meaningless.
	ExitCode() int
}

type mockDebugger struct {
	Debugger

	buf    bytes.Buffer
	failed bool
	err    error
	exited bool
	code   int
}

// InitMockDebugger creates a new MockDebugger for usage in tests.
func InitMockDebugger() MockDebugger {
	md := &mockDebugger{}
	d := initDebugger(true, log.New(&md.buf, "", 0)).(rootDebugger)

	d.fail = func(msgs ...interface{}) {
		md.failed = true
		d.defaultFail(msgs...)
	}

	d.err = func(err error, msgs ...interface{}) {
		if err != nil {
			md.err = err
		}
		d.defaultErr(err, msgs...)
	}

	d.exit = func(code int) {
		md.exited = true
		md.code = code
	}

	md.Debugger = d
	return md
}

func (d *mockDebugger) Output() io.Reader { return &d.buf }
func (d *mockDebugger) Failed() bool      { return d.failed }
func (d *mockDebugger) Err() error        { return d.err }
func (d *mockDebugger) Exited() bool      { return d.exited }
func (d *mockDebugger) ExitCode() int     { return d.code }

var (
	_ Debugger     = rootDebugger{}
	_ Debugger     = prefixedDebugger{}
	_ MockDebugger = &mockDebugger{}
)
