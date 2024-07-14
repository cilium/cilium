// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync/atomic"

	"github.com/cilium/cilium/pkg/time"

	"github.com/cilium/cilium/pkg/lock"
)

// NewConcurrentLogger factory function that returns ConcurrentLogger.
func NewConcurrentLogger(writer io.Writer, concurrency int) *ConcurrentLogger {
	return &ConcurrentLogger{
		messageCh: make(chan message),
		writer:    writer,
		// The concurrency parameter is used for nsTestsCh buffer size calculation.
		// The buffer will be able to accept 10 times more unique connectivity tests
		// than concurrency value. Write to the channel implemented in a separate
		// goroutine to avoid deadlock in case if buffer is full.
		nsTestsCh:        make(chan string, concurrency*10),
		nsTestMsgs:       make(map[string][]message),
		nsTestMsgsLock:   lock.Mutex{},
		collectorStarted: atomic.Bool{},
		printerDoneCh:    make(chan bool),
	}
}

type ConcurrentLogger struct {
	messageCh         chan message
	writer            io.Writer
	nsTestsCh         chan string
	nsTestMsgs        map[string][]message
	nsTestMsgsLock    lock.Mutex
	collectorStarted  atomic.Bool
	printerDoneCh     chan bool
	nsTestFinishCount int
}

// Start starts ConcurrentLogger internals in separate goroutines:
// - collector: collects incoming test messages.
// - printer: sends messages to the writer in corresponding order.
func (c *ConcurrentLogger) Start(ctx context.Context) {
	c.collectorStarted.Store(true)
	go c.collector(ctx)
	go c.printer()
}

// Stop closes incoming message channel and waits while all messages are printed.
func (c *ConcurrentLogger) Stop() {
	close(c.messageCh)
	<-c.printerDoneCh
	close(c.printerDoneCh)
}

type message struct {
	namespace string
	testName  string
	data      string
	finish    bool
}

func (m message) nsTest() string {
	return fmt.Sprintf("%s:%s", m.namespace, m.testName)
}

// Printf schedules message for the test to be printed.
func (c *ConcurrentLogger) Printf(test *Test, format string, args ...interface{}) {
	buf := &bytes.Buffer{}
	if test.ctx.timestamp() {
		mustFprintf(buf, timestamp())
	}
	mustFprintf(buf, format, args...)
	c.messageCh <- message{
		namespace: test.ctx.params.TestNamespace,
		testName:  test.name,
		data:      buf.String(),
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
	c.messageCh <- message{
		namespace: test.Context().Params().TestNamespace,
		testName:  test.Name(),
		data:      buf.String(),
		finish:    true,
	}
}

func (c *ConcurrentLogger) collector(ctx context.Context) {
	defer c.collectorStarted.Store(false)
	for {
		select {
		case m, open := <-c.messageCh:
			if !open {
				return
			}
			nsTest := m.nsTest()
			c.nsTestMsgsLock.Lock()
			nsTestMsgs, ok := c.nsTestMsgs[nsTest]
			if !ok {
				nsTestMsgs = make([]message, 0)
				// use a separate goroutine to avoid deadlock if the channel
				// buffer is full, printer goroutine will pull it eventually
				go func() { c.nsTestsCh <- nsTest }()
			}
			c.nsTestMsgs[nsTest] = append(nsTestMsgs, m)
			c.nsTestMsgsLock.Unlock()
		case <-ctx.Done():
			close(c.messageCh)
			return
		}
	}
}

func (c *ConcurrentLogger) printer() {
	// read messages while the collector is working
	for c.collectorStarted.Load() {
		// double-check if there are new messages to avoid
		// deadlock reading from the `nsTestsCh` channel
		if c.nsTestFinishCount < c.collectedTestCount() {
			c.printTestMessages(<-c.nsTestsCh)
		}
	}
	// collector stopped but there still might be messages to print
	for c.nsTestFinishCount < c.collectedTestCount() {
		c.printTestMessages(<-c.nsTestsCh)
	}
	c.printerDoneCh <- true
	close(c.nsTestsCh)
}

func (c *ConcurrentLogger) collectedTestCount() int {
	c.nsTestMsgsLock.Lock()
	testCount := len(c.nsTestMsgs)
	c.nsTestMsgsLock.Unlock()
	return testCount
}

func (c *ConcurrentLogger) printTestMessages(nsTest string) {
	for printedMessageIndex := 0; ; {
		c.nsTestMsgsLock.Lock()
		messages := c.nsTestMsgs[nsTest]
		c.nsTestMsgsLock.Unlock()
		if len(messages) == printedMessageIndex {
			// wait for new test messages
			time.Sleep(time.Millisecond * 50)
			continue
		}
		for ; printedMessageIndex < len(messages); printedMessageIndex++ {
			mustFprintf(c.writer, messages[printedMessageIndex].data)
			if messages[printedMessageIndex].finish {
				c.nsTestFinishCount++
				return
			}
		}
	}
}

func mustFprintf(writer io.Writer, format string, args ...interface{}) {
	if _, err := fmt.Fprintf(writer, format, args...); err != nil {
		panic(fmt.Errorf("failed to print log message: %w", err))
	}
}
