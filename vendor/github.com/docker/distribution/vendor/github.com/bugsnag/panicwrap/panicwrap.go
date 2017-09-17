// The panicwrap package provides functions for capturing and handling
// panics in your application. It does this by re-executing the running
// application and monitoring stderr for any panics. At the same time,
// stdout/stderr/etc. are set to the same values so that data is shuttled
// through properly, making the existence of panicwrap mostly transparent.
//
// Panics are only detected when the subprocess exits with a non-zero
// exit status, since this is the only time panics are real. Otherwise,
// "panic-like" output is ignored.
package panicwrap

import (
	"bytes"
	"errors"
	"github.com/bugsnag/osext"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"
)

const (
	DEFAULT_COOKIE_KEY = "cccf35992f8f3cd8d1d28f0109dd953e26664531"
	DEFAULT_COOKIE_VAL = "7c28215aca87789f95b406b8dd91aa5198406750"
)

// HandlerFunc is the type called when a panic is detected.
type HandlerFunc func(string)

// WrapConfig is the configuration for panicwrap when wrapping an existing
// binary. To get started, in general, you only need the BasicWrap function
// that will set this up for you. However, for more customizability,
// WrapConfig and Wrap can be used.
type WrapConfig struct {
	// Handler is the function called when a panic occurs.
	Handler HandlerFunc

	// The cookie key and value are used within environmental variables
	// to tell the child process that it is already executing so that
	// wrap doesn't re-wrap itself.
	CookieKey   string
	CookieValue string

	// If true, the panic will not be mirrored to the configured writer
	// and will instead ONLY go to the handler. This lets you effectively
	// hide panics from the end user. This is not recommended because if
	// your handler fails, the panic is effectively lost.
	HidePanic bool

	// If true, panicwrap will boot a monitor sub-process and let the parent
	// run the app. This mode is useful for processes run under supervisors
	// like runit as signals get sent to the correct codebase. This is not
	// supported when GOOS=windows, and ignores c.Stderr and c.Stdout.
	Monitor bool

	// The amount of time that a process must exit within after detecting
	// a panic header for panicwrap to assume it is a panic. Defaults to
	// 300 milliseconds.
	DetectDuration time.Duration

	// The writer to send the stderr to. If this is nil, then it defaults
	// to os.Stderr.
	Writer io.Writer

	// The writer to send stdout to. If this is nil, then it defaults to
	// os.Stdout.
	Stdout io.Writer
}

// BasicWrap calls Wrap with the given handler function, using defaults
// for everything else. See Wrap and WrapConfig for more information on
// functionality and return values.
func BasicWrap(f HandlerFunc) (int, error) {
	return Wrap(&WrapConfig{
		Handler: f,
	})
}

// BasicMonitor calls Wrap with Monitor set to true on supported platforms.
// It forks your program and runs it again form the start. In one process
// BasicMonitor never returns, it just listens on stderr of the other process,
// and calls your handler when a panic is seen. In the other it either returns
// nil to indicate that the panic monitoring is enabled, or an error to indicate
// that something else went wrong.
func BasicMonitor(f HandlerFunc) error {
	exitStatus, err := Wrap(&WrapConfig{
		Handler: f,
		Monitor: runtime.GOOS != "windows",
	})

	if err != nil {
		return err
	}

	if exitStatus >= 0 {
		os.Exit(exitStatus)
	}

	return nil
}

// Wrap wraps the current executable in a handler to catch panics. It
// returns an error if there was an error during the wrapping process.
// If the error is nil, then the int result indicates the exit status of the
// child process. If the exit status is -1, then this is the child process,
// and execution should continue as normal. Otherwise, this is the parent
// process and the child successfully ran already, and you should exit the
// process with the returned exit status.
//
// This function should be called very very early in your program's execution.
// Ideally, this runs as the first line of code of main.
//
// Once this is called, the given WrapConfig shouldn't be modified or used
// any further.
func Wrap(c *WrapConfig) (int, error) {
	if c.Handler == nil {
		return -1, errors.New("Handler must be set")
	}

	if c.DetectDuration == 0 {
		c.DetectDuration = 300 * time.Millisecond
	}

	if c.Writer == nil {
		c.Writer = os.Stderr
	}

	if c.Monitor {
		return monitor(c)
	} else {
		return wrap(c)
	}
}

func wrap(c *WrapConfig) (int, error) {

	// If we're already wrapped, exit out.
	if Wrapped(c) {
		return -1, nil
	}

	// Get the path to our current executable
	exePath, err := osext.Executable()
	if err != nil {
		return -1, err
	}

	// Pipe the stderr so we can read all the data as we look for panics
	stderr_r, stderr_w := io.Pipe()

	// doneCh is closed when we're done, signaling any other goroutines
	// to end immediately.
	doneCh := make(chan struct{})

	// panicCh is the channel on which the panic text will actually be
	// sent.
	panicCh := make(chan string)

	// On close, make sure to finish off the copying of data to stderr
	defer func() {
		defer close(doneCh)
		stderr_w.Close()
		<-panicCh
	}()

	// Start the goroutine that will watch stderr for any panics
	go trackPanic(stderr_r, c.Writer, c.DetectDuration, panicCh)

	// Create the writer for stdout that we're going to use
	var stdout_w io.Writer = os.Stdout
	if c.Stdout != nil {
		stdout_w = c.Stdout
	}

	// Build a subcommand to re-execute ourselves. We make sure to
	// set the environmental variable to include our cookie. We also
	// set stdin/stdout to match the config. Finally, we pipe stderr
	// through ourselves in order to watch for panics.
	cmd := exec.Command(exePath, os.Args[1:]...)
	cmd.Env = append(os.Environ(), c.CookieKey+"="+c.CookieValue)
	cmd.Stdin = os.Stdin
	cmd.Stdout = stdout_w
	cmd.Stderr = stderr_w
	if err := cmd.Start(); err != nil {
		return 1, err
	}

	// Listen to signals and capture them forever. We allow the child
	// process to handle them in some way.
	sigCh := make(chan os.Signal)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		defer signal.Stop(sigCh)
		for {
			select {
			case <-doneCh:
				return
			case <-sigCh:
			}
		}
	}()

	if err := cmd.Wait(); err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			// This is some other kind of subprocessing error.
			return 1, err
		}

		exitStatus := 1
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
			exitStatus = status.ExitStatus()
		}

		// Close the writer end so that the tracker goroutine ends at some point
		stderr_w.Close()

		// Wait on the panic data
		panicTxt := <-panicCh
		if panicTxt != "" {
			if !c.HidePanic {
				c.Writer.Write([]byte(panicTxt))
			}

			c.Handler(panicTxt)
		}

		return exitStatus, nil
	}

	return 0, nil
}

// Wrapped checks if we're already wrapped according to the configuration
// given.
//
// Wrapped is very cheap and can be used early to short-circuit some pre-wrap
// logic your application may have.
func Wrapped(c *WrapConfig) bool {
	if c.CookieKey == "" {
		c.CookieKey = DEFAULT_COOKIE_KEY
	}

	if c.CookieValue == "" {
		c.CookieValue = DEFAULT_COOKIE_VAL
	}

	// If the cookie key/value match our environment, then we are the
	// child, so just exit now and tell the caller that we're the child
	return os.Getenv(c.CookieKey) == c.CookieValue
}

// trackPanic monitors the given reader for a panic. If a panic is detected,
// it is outputted on the result channel. This will close the channel once
// it is complete.
func trackPanic(r io.Reader, w io.Writer, dur time.Duration, result chan<- string) {
	defer close(result)

	var panicTimer <-chan time.Time
	panicBuf := new(bytes.Buffer)
	panicHeader := []byte("panic:")

	tempBuf := make([]byte, 2048)
	for {
		var buf []byte
		var n int

		if panicTimer == nil && panicBuf.Len() > 0 {
			// We're not tracking a panic but the buffer length is
			// greater than 0. We need to clear out that buffer, but
			// look for another panic along the way.

			// First, remove the previous panic header so we don't loop
			w.Write(panicBuf.Next(len(panicHeader)))

			// Next, assume that this is our new buffer to inspect
			n = panicBuf.Len()
			buf = make([]byte, n)
			copy(buf, panicBuf.Bytes())
			panicBuf.Reset()
		} else {
			var err error
			buf = tempBuf
			n, err = r.Read(buf)
			if n <= 0 && err == io.EOF {
				if panicBuf.Len() > 0 {
					// We were tracking a panic, assume it was a panic
					// and return that as the result.
					result <- panicBuf.String()
				}

				return
			}
		}

		if panicTimer != nil {
			// We're tracking what we think is a panic right now.
			// If the timer ended, then it is not a panic.
			isPanic := true
			select {
			case <-panicTimer:
				isPanic = false
			default:
			}

			// No matter what, buffer the text some more.
			panicBuf.Write(buf[0:n])

			if !isPanic {
				// It isn't a panic, stop tracking. Clean-up will happen
				// on the next iteration.
				panicTimer = nil
			}

			continue
		}

		flushIdx := n
		idx := bytes.Index(buf[0:n], panicHeader)
		if idx >= 0 {
			flushIdx = idx
		}

		// Flush to stderr what isn't a panic
		w.Write(buf[0:flushIdx])

		if idx < 0 {
			// Not a panic so just continue along
			continue
		}

		// We have a panic header. Write we assume is a panic os far.
		panicBuf.Write(buf[idx:n])
		panicTimer = time.After(dur)
	}
}
