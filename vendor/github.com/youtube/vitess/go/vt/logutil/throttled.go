package logutil

import (
	"fmt"
	"sync"
	"time"

	log "github.com/golang/glog"
)

// ThrottledLogger will allow logging of messages but won't spam the
// logs.
type ThrottledLogger struct {
	// set at construction
	name        string
	maxInterval time.Duration

	// mu protects the following members
	mu           sync.Mutex
	lastlogTime  time.Time
	skippedCount int
}

// NewThrottledLogger will create a ThrottledLogger with the given
// name and throttling interval.
func NewThrottledLogger(name string, maxInterval time.Duration) *ThrottledLogger {
	return &ThrottledLogger{
		name:        name,
		maxInterval: maxInterval,
	}
}

type logFunc func(int, ...interface{})

var (
	infoDepth    = log.InfoDepth
	warningDepth = log.WarningDepth
	errorDepth   = log.ErrorDepth
)

func (tl *ThrottledLogger) log(logF logFunc, format string, v ...interface{}) {
	now := time.Now()

	tl.mu.Lock()
	defer tl.mu.Unlock()
	logWaitTime := tl.maxInterval - (now.Sub(tl.lastlogTime))
	if logWaitTime < 0 {
		tl.lastlogTime = now
		logF(2, fmt.Sprintf(tl.name+": "+format, v...))
		return
	}
	// If this is the first message to be skipped, start a goroutine
	// to log and reset skippedCount
	if tl.skippedCount == 0 {
		go func(d time.Duration) {
			time.Sleep(d)
			tl.mu.Lock()
			defer tl.mu.Unlock()
			// Because of the go func(), we lose the stack trace,
			// so we just use the current line for this.
			logF(0, fmt.Sprintf("%v: skipped %v log messages", tl.name, tl.skippedCount))
			tl.skippedCount = 0
		}(logWaitTime)
	}
	tl.skippedCount++
}

// Infof logs an info if not throttled.
func (tl *ThrottledLogger) Infof(format string, v ...interface{}) {
	tl.log(infoDepth, format, v...)
}

// Warningf logs a warning if not throttled.
func (tl *ThrottledLogger) Warningf(format string, v ...interface{}) {
	tl.log(warningDepth, format, v...)
}

// Errorf logs an error if not throttled.
func (tl *ThrottledLogger) Errorf(format string, v ...interface{}) {
	tl.log(errorDepth, format, v...)
}
