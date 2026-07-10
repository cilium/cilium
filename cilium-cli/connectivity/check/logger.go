// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"bytes"
	"fmt"
	"io"
)

// NewConcurrentLogger factory function that returns ConcurrentLogger.
func NewConcurrentLogger(writer io.Writer) *ConcurrentLogger {
	return &ConcurrentLogger{
		writer:   writer,
		messages: make(chan message),
		done:     make(chan struct{}),
	}
}

type ConcurrentLogger struct {
	writer   io.Writer
	messages chan message
	done     chan struct{}
}

// Start starts ConcurrentLogger
func (c *ConcurrentLogger) Start() {
	go func() {
		// current is the test that is currently being streamed to the writer without
		// buffering
		var current *Test

		// buffered is a map of tests (other than current one) that have not finished yet
		buffered := make(map[*Test]*bytes.Buffer)

		// finished is an ordered list of tests to be logged once the current test finishes
		var finished []*bytes.Buffer

		for m := range c.messages {
			// make this the current test if none
			if current == nil {
				current = m.test
			}

			// stream the current test without buffering
			if m.test == current {
				mustWrite(c.writer, m.data)
				if m.finish {
					current = nil
				}
			} else {
				// buffer other tests
				buf, ok := buffered[m.test]
				if !ok {
					buf = &bytes.Buffer{}
					buffered[m.test] = buf
				}
				mustWrite(buf, m.data)
				if m.finish {
					delete(buffered, m.test)
					finished = append(finished, buf)
				}
			}

			if current == nil {
				// log any finished tests after done with the current test
				for _, buf := range finished {
					mustWrite(c.writer, buf.Bytes())
				}
				finished = finished[len(finished):]

				// pick one of the running tests as the current one, if any
				for test, buf := range buffered {
					delete(buffered, test)
					mustWrite(c.writer, buf.Bytes())
					current = test
					break
				}
			}
		}
		// No more messages, log all remaining messages
		for _, buf := range finished {
			mustWrite(c.writer, buf.Bytes())
		}
		for _, buf := range buffered {
			mustWrite(c.writer, buf.Bytes())
		}
		close(c.done)
	}()
}

// Stop closes incoming message channel and waits while all messages are printed.
func (c *ConcurrentLogger) Stop() {
	close(c.messages)
	<-c.done
}

type message struct {
	test   *Test
	data   []byte
	finish bool
}

// Print schedules message for the test to be printed.
func (c *ConcurrentLogger) Print(test *Test, msg []byte) {
	if test.ctx.timestamp() {
		msg = append(timestampBytes(), msg...)
	}
	c.messages <- message{
		test: test,
		data: msg,
	}
}

// Printf schedules message for the test to be printed.
func (c *ConcurrentLogger) Printf(test *Test, format string, args ...any) {
	buf := &bytes.Buffer{}
	if test.ctx.timestamp() {
		mustWrite(buf, timestampBytes())
	}
	mustFprintf(buf, format, args...)
	c.messages <- message{
		test: test,
		data: buf.Bytes(),
	}
}

// FinishTest schedules the final message for the test to be printed.
// The message will be populated with the test log buffer if the test failed.
func (c *ConcurrentLogger) FinishTest(test *Test) {
	buf := &bytes.Buffer{}
	if test.failed && test.logBuf != nil {
		if _, err := io.Copy(buf, test.logBuf); err != nil {
			panic(fmt.Errorf("failed to read from test log buffer: %w", err))
		}
	}
	c.messages <- message{
		test:   test,
		data:   buf.Bytes(),
		finish: true,
	}
}

func mustWrite(writer io.Writer, msg []byte) {
	if _, err := writer.Write(msg); err != nil {
		panic(fmt.Errorf("failed to print log message: %w", err))
	}
}
func mustFprintf(writer io.Writer, format string, args ...any) {
	if _, err := fmt.Fprintf(writer, format, args...); err != nil {
		panic(fmt.Errorf("failed to print log message: %w", err))
	}
}
