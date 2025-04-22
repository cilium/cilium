// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/cilium/cilium/cilium-cli/utils/codeowners"
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
	Log(a ...any)
	// Logf logs a formatted message.
	Logf(format string, a ...any)

	// Debug logs a debug message.
	Debug(a ...any)
	// Debugf logs a formatted debug message.
	Debugf(format string, a ...any)

	// Info logs an informational message.
	Info(a ...any)
	// Infof logs a formatted informational message.
	Infof(format string, a ...any)
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
func (ct *ConnectivityTest) Header(a ...any) {
	fmt.Fprintln(ct.params.Writer, "")
	fmt.Fprintln(ct.params.Writer, a...)
}

// Headerf prints a newline followed by a formatted message.
func (ct *ConnectivityTest) Headerf(format string, a ...any) {
	fmt.Fprintf(ct.params.Writer, "\n"+format+"\n", a...)
}

// Timestamp logs the current timestamp.
func (ct *ConnectivityTest) Timestamp() {
	if ct.timestamp() {
		fmt.Fprint(ct.params.Writer, timestamp())
	}
}

// Log logs a message.
func (ct *ConnectivityTest) Log(a ...any) {
	ct.Timestamp()
	fmt.Fprintln(ct.params.Writer, a...)
}

var defaultTestOwners codeowners.Scenario

func init() {
	// Initialize in an init func to ensure that NewScenarioBase() can look
	// up a couple of layers of stack to find a test file in order to
	// determine default codeowners, in this case falling back to the
	// owners of the overall test infrastructure.
	//
	// This will be used when there is a failure outside of a specific
	// scenario provided by a test.
	defaultTestOwners = defaultScenario{
		ScenarioBase: NewScenarioBase(),
	}
}

type defaultScenario struct {
	ScenarioBase
}

func (s defaultScenario) Name() string {
	return "cli-test-framework"
}

func (ct *ConnectivityTest) LogOwners(scenarios ...codeowners.Scenario) {
	owners, err := ct.CodeOwners.Owners(true, scenarios...)
	if err != nil {
		ct.Logf("Failed to find CODEOWNERS for test scenario: %s", err)
	}
	if len(owners) == 0 {
		return
	}

	ct.Log("    ⛑️ The following owners are responsible for reliability of the testsuite: ")
	for _, o := range owners {
		ct.Log("        - " + o)
	}

	workflowOwners, err := ct.CodeOwners.WorkflowOwners(true)
	if err != nil {
		ct.Logf("Failed to find CODEOWNERS for github workflow: %s", err)
	}
	for _, o := range workflowOwners {
		ct.Log("        - " + o)
	}
}

// Logf logs a formatted message.
func (ct *ConnectivityTest) Logf(format string, a ...any) {
	ct.Timestamp()
	fmt.Fprintf(ct.params.Writer, format+"\n", a...)
}

// Debug logs a debug message.
func (ct *ConnectivityTest) Debug(a ...any) {
	if ct.debug() {
		ct.Timestamp()
		fmt.Fprint(ct.params.Writer, debug+" ")
		fmt.Fprintln(ct.params.Writer, a...)
	}
}

// Debugf logs a formatted debug message.
func (ct *ConnectivityTest) Debugf(format string, a ...any) {
	if ct.debug() {
		ct.Timestamp()
		fmt.Fprint(ct.params.Writer, debug+" ")
		fmt.Fprintf(ct.params.Writer, format+"\n", a...)
	}
}

// Info logs an informational message.
func (ct *ConnectivityTest) Info(a ...any) {
	ct.Timestamp()
	fmt.Fprint(ct.params.Writer, info+" ")
	fmt.Fprintln(ct.params.Writer, a...)
}

// Infof logs a formatted informational message.
func (ct *ConnectivityTest) Infof(format string, a ...any) {
	ct.Timestamp()
	fmt.Fprint(ct.params.Writer, info+" ")
	fmt.Fprintf(ct.params.Writer, format+"\n", a...)
}

// Warn logs a warning message.
func (ct *ConnectivityTest) Warn(a ...any) {
	ct.Timestamp()
	fmt.Fprint(ct.params.Writer, warn+" ")
	fmt.Fprintln(ct.params.Writer, a...)
}

// Warnf logs a formatted warning message.
func (ct *ConnectivityTest) Warnf(format string, a ...any) {
	ct.Timestamp()
	fmt.Fprint(ct.params.Writer, warn+" ")
	fmt.Fprintf(ct.params.Writer, format+"\n", a...)
}

// Fail logs a failure message.
func (ct *ConnectivityTest) Fail(a ...any) {
	ct.Timestamp()
	fmt.Fprint(ct.params.Writer, fail+" ")
	fmt.Fprintln(ct.params.Writer, a...)
}

// Failf logs a formatted failure message.
func (ct *ConnectivityTest) Failf(format string, a ...any) {
	ct.Timestamp()
	fmt.Fprint(ct.params.Writer, fail+" ")
	fmt.Fprintf(ct.params.Writer, format+"\n", a...)
}

// Fatal logs an error.
func (ct *ConnectivityTest) Fatal(a ...any) {
	ct.Timestamp()
	fmt.Fprint(ct.params.Writer, fatal+" ")
	fmt.Fprintln(ct.params.Writer, a...)
}

// Fatalf logs a formatted error.
func (ct *ConnectivityTest) Fatalf(format string, a ...any) {
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

// log takes out a read lock and logs a message to the Test's internal buffer.
// If the internal log buffer is nil, write to user-specified writer instead.
// Prefix is an optional prefix to the message.
func (t *Test) log(prefix string, a ...any) {
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
func (t *Test) logf(format string, a ...any) {
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

	buf := &bytes.Buffer{}
	if _, err := io.Copy(buf, t.logBuf); err != nil {
		panic(err)
	}
	t.ctx.logger.Print(t, buf.Bytes())

	// Assign a nil buffer so future writes go to user-specified writer.
	t.logBuf = nil
}

// Log logs a message.
func (t *Test) Log(a ...any) {
	t.log("", a...)
}

// Logf logs a formatted message.
func (t *Test) Logf(format string, a ...any) {
	t.logf(format, a...)
}

// Debug logs a debug message.
func (t *Test) Debug(a ...any) {
	if t.ctx.debug() {
		t.log(debug, a...)
	}
}

// Debugf logs a formatted debug message.
func (t *Test) Debugf(format string, a ...any) {
	if t.ctx.debug() {
		t.logf(debug+" "+format, a...)
	}
}

// Info logs an informational message.
func (t *Test) Info(a ...any) {
	t.log(info, a...)
}

// Infof logs a formatted informational message.
func (t *Test) Infof(format string, a ...any) {
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
func (t *Test) Fail(a ...any) {
	t.log(fail, a...)
	t.failCommon()
}

// Failf marks the Test as failed and logs a formatted failure message.
//
// Flushes the Test's internal log buffer. Any further logs against the Test
// will go directly to the user-specified writer.
func (t *Test) Failf(format string, a ...any) {
	t.logf(fail+" "+format, a...)
	t.failCommon()
}

// Fatal marks the test as failed, logs an error and exits the
// calling goroutine.
func (t *Test) Fatal(a ...any) {
	t.log(fatal, a...)
	t.failCommon()
	runtime.Goexit()
}

// Fatalf marks the test as failed, logs a formatted error and exits the
// calling goroutine.
func (t *Test) Fatalf(format string, a ...any) {
	t.logf(fatal+" "+format, a...)
	t.failCommon()
	runtime.Goexit()
}

//
// Output methods on an Action scope.
//

// Log logs a message.
func (a *Action) Log(s ...any) {
	a.test.Log(s...)
}

// Logf logs a formatted message.
func (a *Action) Logf(format string, s ...any) {
	a.test.Logf(format, s...)
}

// Debug logs a debug message.
func (a *Action) Debug(s ...any) {
	if a.test.ctx.debug() {
		a.test.Debug(s...)
	}
}

// Debugf logs a formatted debug message.
func (a *Action) Debugf(format string, s ...any) {
	if a.test.ctx.debug() {
		a.test.Debugf(format, s...)
	}
}

// Info logs a debug message.
func (a *Action) Info(s ...any) {
	a.test.Info(s...)
}

// Infof logs a formatted debug message.
func (a *Action) Infof(format string, s ...any) {
	a.test.Infof(format, s...)
}

// Fail must be called when the Action is unsuccessful.
func (a *Action) Fail(s ...any) {
	a.fail()
	a.test.Fail(s...)
}

// Failf must be called when the Action is unsuccessful.
func (a *Action) Failf(format string, s ...any) {
	a.fail()
	a.test.Failf(format, s...)
}

// Fatal must be called when an irrecoverable error was encountered during the Action.
func (a *Action) Fatal(s ...any) {
	a.fail()
	a.test.Fatal(s...)
}

// Fatalf must be called when an irrecoverable error was encountered during the Action.
func (a *Action) Fatalf(format string, s ...any) {
	a.fail()
	a.test.Fatalf(format, s...)
}

func timestamp() string {
	return fmt.Sprintf("[%s] ", time.Now().Format(time.RFC3339))
}

func timestampBytes() []byte {
	b := make([]byte, 0, 32) // roughly enough space
	b = append(b, '[')
	b = time.Now().AppendFormat(b, time.RFC3339)
	b = append(b, ']', ' ')
	return b
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
