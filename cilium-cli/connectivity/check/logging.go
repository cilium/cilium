// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"
)

const (
	debug = "🐛"
	info  = "ℹ️ "
	warn  = "⚠️ "
	fail  = "❌"
	fatal = "🟥"

	testPrefix = "  "
)

// Logger abstracts the logging functionalities implemented by the
// test suite, individual tests and actions.
type Logger interface {
	// Log logs a message.
	Log(a ...interface{})
	// Logf logs a formatted message.
	Logf(format string, a ...interface{})

	// Debug logs a debug message.
	Debug(a ...interface{})
	// Debugf logs a formatted debug message.
	Debugf(format string, a ...interface{})

	// Info logs an informational message.
	Info(a ...interface{})
	// Infof logs a formatted informational message.
	Infof(format string, a ...interface{})
}

var _ Logger = (*ConnectivityTest)(nil)
var _ Logger = (*Test)(nil)
var _ Logger = (*Action)(nil)

//
// Output methods on the global ConnectivityTest context.
// These methods never buffer any lines and are sent directly to the
// user-specified writer.
//

// Header prints a newline followed by a formatted message.
func (ct *ConnectivityTest) Header(a ...interface{}) {
	fmt.Fprintln(ct.params.Writer, "")
	fmt.Fprintln(ct.params.Writer, a...)
}

// Headerf prints a newline followed by a formatted message.
func (ct *ConnectivityTest) Headerf(format string, a ...interface{}) {
	fmt.Fprintf(ct.params.Writer, "\n"+format+"\n", a...)
}

// Timestamps logs the current timestamp.
func (ct *ConnectivityTest) Timestamp() {
	if ct.timestamp() {
		fmt.Fprint(ct.params.Writer, timestamp())
	}
}

// Log logs a message.
func (ct *ConnectivityTest) Log(a ...interface{}) {
	ct.Timestamp()
	fmt.Fprintln(ct.params.Writer, a...)
}

// Logf logs a formatted message.
func (ct *ConnectivityTest) Logf(format string, a ...interface{}) {
	ct.Timestamp()
	fmt.Fprintf(ct.params.Writer, format+"\n", a...)
}

// Debug logs a debug message.
func (ct *ConnectivityTest) Debug(a ...interface{}) {
	if ct.debug() {
		ct.Timestamp()
		fmt.Fprint(ct.params.Writer, debug+" ")
		fmt.Fprintln(ct.params.Writer, a...)
	}
}

// Debugf logs a formatted debug message.
func (ct *ConnectivityTest) Debugf(format string, a ...interface{}) {
	if ct.debug() {
		ct.Timestamp()
		fmt.Fprint(ct.params.Writer, debug+" ")
		fmt.Fprintf(ct.params.Writer, format+"\n", a...)
	}
}

// Info logs an informational message.
func (ct *ConnectivityTest) Info(a ...interface{}) {
	ct.Timestamp()
	fmt.Fprint(ct.params.Writer, info+" ")
	fmt.Fprintln(ct.params.Writer, a...)
}

// Infof logs a formatted informational message.
func (ct *ConnectivityTest) Infof(format string, a ...interface{}) {
	ct.Timestamp()
	fmt.Fprint(ct.params.Writer, info+" ")
	fmt.Fprintf(ct.params.Writer, format+"\n", a...)
}

// Warn logs a warning message.
func (ct *ConnectivityTest) Warn(a ...interface{}) {
	ct.Timestamp()
	fmt.Fprint(ct.params.Writer, warn+" ")
	fmt.Fprintln(ct.params.Writer, a...)
}

// Warnf logs a formatted warning message.
func (ct *ConnectivityTest) Warnf(format string, a ...interface{}) {
	ct.Timestamp()
	fmt.Fprint(ct.params.Writer, warn+" ")
	fmt.Fprintf(ct.params.Writer, format+"\n", a...)
}

// Fail logs a failure message.
func (ct *ConnectivityTest) Fail(a ...interface{}) {
	ct.Timestamp()
	fmt.Fprint(ct.params.Writer, fail+" ")
	fmt.Fprintln(ct.params.Writer, a...)
}

// Failf logs a formatted failure message.
func (ct *ConnectivityTest) Failf(format string, a ...interface{}) {
	ct.Timestamp()
	fmt.Fprint(ct.params.Writer, fail+" ")
	fmt.Fprintf(ct.params.Writer, format+"\n", a...)
}

// Fatal logs an error.
func (ct *ConnectivityTest) Fatal(a ...interface{}) {
	ct.Timestamp()
	fmt.Fprint(ct.params.Writer, fatal+" ")
	fmt.Fprintln(ct.params.Writer, a...)
}

// Fatalf logs a formatted error.
func (ct *ConnectivityTest) Fatalf(format string, a ...interface{}) {
	ct.Timestamp()
	fmt.Fprint(ct.params.Writer, fatal+" ")
	fmt.Fprintf(ct.params.Writer, format+"\n", a...)
}

//
// Output methods on an individual test scope.
// Some of these methods will buffer content until a test is marked as failed.
// Test code should never call the output methods of ConnectivityTest, and
// should always call the methods implemented on Test.
//

// progress outputs an unbuffered progress indicator if logging is buffered.
func (t *Test) progress() {
	t.logMu.RLock()
	defer t.logMu.RUnlock()

	// Skip progress indicator if logging is not buffered.
	if t.logBuf == nil {
		return
	}

	fmt.Fprint(t.ctx.params.Writer, ".")
}

// log takes out a read lock and logs a message to the Test's internal buffer.
// If the internal log buffer is nil, write to user-specified writer instead.
// Prefix is an optional prefix to the message.
func (t *Test) log(prefix string, a ...interface{}) {
	t.logMu.RLock()
	defer t.logMu.RUnlock()

	b := t.logBuf
	if b == nil {
		b = t.ctx.params.Writer
	}

	if t.ctx.timestamp() {
		fmt.Fprint(b, timestamp())
	}

	// Test-level output is indented.
	fmt.Fprint(b, testPrefix)

	// Output the prefix specified by the caller.
	if prefix != "" {
		fmt.Fprint(b, prefix+" ")
	}

	fmt.Fprintln(b, a...)
}

// logf takes out a read lock and logs a formatted message to the Test's
// internal buffer. If the internal log buffer is nil, write to user-specified
// writer instead.
func (t *Test) logf(format string, a ...interface{}) {
	t.logMu.RLock()
	defer t.logMu.RUnlock()

	b := t.logBuf
	if b == nil {
		b = t.ctx.params.Writer
	}

	if t.ctx.timestamp() {
		fmt.Fprint(b, timestamp())
	}

	fmt.Fprintf(b, testPrefix+format+"\n", a...)
}

func (t *Test) flush() {
	// Prevent any other messages from being written to the Test buffer.
	t.logMu.Lock()
	defer t.logMu.Unlock()

	// Nil buffer means we're already sending to user-specified writer.
	if t.logBuf == nil {
		return
	}

	// Terminate progress so far.
	fmt.Fprintln(t.ctx.params.Writer)

	// Flush internal buffer to user-specified writer.
	if _, err := io.Copy(t.ctx.params.Writer, t.logBuf); err != nil {
		panic(err)
	}

	// Assign a nil buffer so future writes go to user-specified writer.
	t.logBuf = nil
}

// Headerf prints a formatted, indented header inside the test log scope.
// Headers are not internally buffered.
func (t *Test) Headerf(format string, a ...interface{}) {
	t.ctx.Headerf(testPrefix+format, a...)
}

// Log logs a message.
func (t *Test) Log(a ...interface{}) {
	t.log("", a...)
}

// Logf logs a formatted message.
func (t *Test) Logf(format string, a ...interface{}) {
	t.logf(format, a...)
}

// Debug logs a debug message.
func (t *Test) Debug(a ...interface{}) {
	if t.ctx.debug() {
		t.log(debug, a...)
	}
}

// Debugf logs a formatted debug message.
func (t *Test) Debugf(format string, a ...interface{}) {
	if t.ctx.debug() {
		t.logf(debug+" "+format, a...)
	}
}

// Info logs an informational message.
func (t *Test) Info(a ...interface{}) {
	t.log(info, a...)
}

// Infof logs a formatted informational message.
func (t *Test) Infof(format string, a ...interface{}) {
	t.logf(info+" "+format, a...)
}

func (t *Test) failCommon() {
	alreadyFailed := t.failed
	t.failed = true
	t.flush()
	if t.ctx.params.PauseOnFail {
		t.log("Pausing after action failure, press the Enter key to continue:")
		cont := make(chan struct{})
		go func() {
			fmt.Scanln()
			close(cont)
		}()
		ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		select {
		case <-cont:
		case <-ctx.Done():
		}
	}
	if t.ctx.params.CollectSysdumpOnFailure &&
		(t.sysdumpPolicy == SysdumpPolicyEach || (t.sysdumpPolicy == SysdumpPolicyOnce && !alreadyFailed)) {
		t.collectSysdump()
	}
}

// Fail marks the Test as failed and logs a failure message.
//
// Flushes the Test's internal log buffer. Any further logs against the Test
// will go directly to the user-specified writer.
func (t *Test) Fail(a ...interface{}) {
	t.log(fail, a...)
	t.failCommon()
}

// Failf marks the Test as failed and logs a formatted failure message.
//
// Flushes the Test's internal log buffer. Any further logs against the Test
// will go directly to the user-specified writer.
func (t *Test) Failf(format string, a ...interface{}) {
	t.logf(fail+" "+format, a...)
	t.failCommon()
}

// Fatal marks the test as failed, logs an error and exits the
// calling goroutine.
func (t *Test) Fatal(a ...interface{}) {
	t.log(fatal, a...)
	t.failCommon()
	runtime.Goexit()
}

// Fatalf marks the test as failed, logs a formatted error and exits the
// calling goroutine.
func (t *Test) Fatalf(format string, a ...interface{}) {
	t.logf(fatal+" "+format, a...)
	t.failCommon()
	runtime.Goexit()
}

//
// Output methods on an Action scope.
//

// Log logs a message.
func (a *Action) Log(s ...interface{}) {
	a.test.Log(s...)
}

// Logf logs a formatted message.
func (a *Action) Logf(format string, s ...interface{}) {
	a.test.Logf(format, s...)
}

// Debug logs a debug message.
func (a *Action) Debug(s ...interface{}) {
	if a.test.ctx.debug() {
		a.test.Debug(s...)
	}
}

// Debugf logs a formatted debug message.
func (a *Action) Debugf(format string, s ...interface{}) {
	if a.test.ctx.debug() {
		a.test.Debugf(format, s...)
	}
}

// Info logs a debug message.
func (a *Action) Info(s ...interface{}) {
	a.test.Info(s...)
}

// Infof logs a formatted debug message.
func (a *Action) Infof(format string, s ...interface{}) {
	a.test.Infof(format, s...)
}

// Fail must be called when the Action is unsuccessful.
func (a *Action) Fail(s ...interface{}) {
	a.fail()
	a.test.Fail(s...)
}

// Failf must be called when the Action is unsuccessful.
func (a *Action) Failf(format string, s ...interface{}) {
	a.fail()
	a.test.Failf(format, s...)
}

// Fatal must be called when an irrecoverable error was encountered during the Action.
func (a *Action) Fatal(s ...interface{}) {
	a.fail()
	a.test.Fatal(s...)
}

// Fatalf must be called when an irrecoverable error was encountered during the Action.
func (a *Action) Fatalf(format string, s ...interface{}) {
	a.fail()
	a.test.Fatalf(format, s...)
}

// DebugEnabled returns whether debug logging is enabled.
func (a *Action) DebugEnabled() bool {
	return a.test.ctx.debug()
}

func timestamp() string {
	return fmt.Sprintf("[%s] ", time.Now().Format(time.RFC3339))
}

type debugWriter struct {
	ct *ConnectivityTest
}

func (d *debugWriter) Write(b []byte) (int, error) {
	d.ct.Debug(string(b))
	return len(b), nil
}

type warnWriter struct {
	ct *ConnectivityTest
}

func (w *warnWriter) Write(b []byte) (int, error) {
	w.ct.Warn(string(b))
	return len(b), nil
}
