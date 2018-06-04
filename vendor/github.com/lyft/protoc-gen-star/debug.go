package pgs

import (
	"fmt"
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

type errFunc func(err error, msgs ...string)

type failFunc func(msgs ...string)

type rootDebugger struct {
	err       errFunc
	fail      failFunc
	l         logger
	logDebugs bool
}

func initDebugger(g *Generator, l logger) Debugger {
	return rootDebugger{
		err:       g.pgg.Error,
		fail:      g.pgg.Fail,
		logDebugs: g.debug,
		l:         l,
	}
}

func (d rootDebugger) Log(v ...interface{})                  { d.l.Println(v...) }
func (d rootDebugger) Logf(format string, v ...interface{})  { d.l.Printf(format, v...) }
func (d rootDebugger) Fail(v ...interface{})                 { d.fail(fmt.Sprint(v...)) }
func (d rootDebugger) Failf(format string, v ...interface{}) { d.fail(fmt.Sprintf(format, v...)) }
func (d rootDebugger) Exit(code int)                         { os.Exit(code) }

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

var _ Debugger = rootDebugger{}
var _ Debugger = prefixedDebugger{}
