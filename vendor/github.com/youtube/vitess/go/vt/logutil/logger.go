package logutil

import (
	"bytes"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync"
	"time"

	logutilpb "github.com/youtube/vitess/go/vt/proto/logutil"
)

// Logger defines the interface to use for our logging interface.
// All methods should be thread safe (i.e. multiple go routines can
// call these methods simultaneously).
type Logger interface {
	// Infof logs at INFO level. A newline is appended if missing.
	Infof(format string, v ...interface{})
	// Warningf logs at WARNING level. A newline is appended if missing.
	Warningf(format string, v ...interface{})
	// Errorf logs at ERROR level. A newline is appended if missing.
	Errorf(format string, v ...interface{})

	// Printf will just display information on stdout when possible.
	// No newline is appended.
	Printf(format string, v ...interface{})

	// InfoDepth allows call frame depth to be adjusted when logging to INFO.
	InfoDepth(depth int, s string)
	// WarningDepth allows call frame depth to be adjusted when logging to WARNING.
	WarningDepth(depth int, s string)
	// ErrorDepth allows call frame depth to be adjusted when logging to ERROR.
	ErrorDepth(depth int, s string)
}

// EventToBuffer formats an individual Event into a buffer, without the
// final '\n'
func EventToBuffer(event *logutilpb.Event, buf *bytes.Buffer) {
	// Avoid Fprintf, for speed. The format is so simple that we
	// can do it quickly by hand.  It's worth about 3X. Fprintf is hard.

	// Lmmdd hh:mm:ss.uuuuuu file:line]
	switch event.Level {
	case logutilpb.Level_INFO:
		buf.WriteByte('I')
	case logutilpb.Level_WARNING:
		buf.WriteByte('W')
	case logutilpb.Level_ERROR:
		buf.WriteByte('E')
	case logutilpb.Level_CONSOLE:
		buf.WriteString(event.Value)
		return
	}

	t := ProtoToTime(event.Time)
	_, month, day := t.Date()
	hour, minute, second := t.Clock()
	twoDigits(buf, int(month))
	twoDigits(buf, day)
	buf.WriteByte(' ')
	twoDigits(buf, hour)
	buf.WriteByte(':')
	twoDigits(buf, minute)
	buf.WriteByte(':')
	twoDigits(buf, second)
	buf.WriteByte('.')
	nDigits(buf, 6, t.Nanosecond()/1000, '0')
	buf.WriteByte(' ')
	buf.WriteString(event.File)
	buf.WriteByte(':')
	someDigits(buf, event.Line)
	buf.WriteByte(']')
	buf.WriteByte(' ')
	buf.WriteString(event.Value)
}

// EventString returns the line in one string
func EventString(event *logutilpb.Event) string {
	buf := new(bytes.Buffer)
	EventToBuffer(event, buf)
	return buf.String()
}

// LogEvent sends an event to a Logger, using the level specified in the event.
// The event struct is converted to a string with EventString().
func LogEvent(logger Logger, event *logutilpb.Event) {
	switch event.Level {
	case logutilpb.Level_INFO:
		logger.InfoDepth(1, EventString(event))
	case logutilpb.Level_WARNING:
		logger.WarningDepth(1, EventString(event))
	case logutilpb.Level_ERROR:
		logger.ErrorDepth(1, EventString(event))
	case logutilpb.Level_CONSOLE:
		// Note we can't just pass the string, because it might contain '%'.
		logger.Printf("%s", EventString(event))
	}
}

// CallbackLogger is a logger that sends the logging event to a callback
// for consumption.
type CallbackLogger struct {
	f func(*logutilpb.Event)
}

// NewCallbackLogger returns a new logger to the given callback.
// Note this and the other objects using this object should either
// all use pointer receivers, or non-pointer receivers.
// (that is ChannelLogger and MemoryLogger). That way they can share the
// 'depth' parameter freely. In this code now, they all use pointer receivers.
func NewCallbackLogger(f func(*logutilpb.Event)) *CallbackLogger {
	return &CallbackLogger{f}
}

// InfoDepth is part of the Logger interface.
func (cl *CallbackLogger) InfoDepth(depth int, s string) {
	file, line := fileAndLine(2 + depth)
	cl.f(&logutilpb.Event{
		Time:  TimeToProto(time.Now()),
		Level: logutilpb.Level_INFO,
		File:  file,
		Line:  line,
		Value: s,
	})
}

// WarningDepth is part of the Logger interface
func (cl *CallbackLogger) WarningDepth(depth int, s string) {
	file, line := fileAndLine(2 + depth)
	cl.f(&logutilpb.Event{
		Time:  TimeToProto(time.Now()),
		Level: logutilpb.Level_WARNING,
		File:  file,
		Line:  line,
		Value: s,
	})
}

// ErrorDepth is part of the Logger interface
func (cl *CallbackLogger) ErrorDepth(depth int, s string) {
	file, line := fileAndLine(2 + depth)
	cl.f(&logutilpb.Event{
		Time:  TimeToProto(time.Now()),
		Level: logutilpb.Level_ERROR,
		File:  file,
		Line:  line,
		Value: s,
	})
}

// Infof is part of the Logger interface.
func (cl *CallbackLogger) Infof(format string, v ...interface{}) {
	cl.InfoDepth(1, fmt.Sprintf(format, v...))
}

// Warningf is part of the Logger interface.
func (cl *CallbackLogger) Warningf(format string, v ...interface{}) {
	cl.WarningDepth(1, fmt.Sprintf(format, v...))
}

// Errorf is part of the Logger interface.
func (cl *CallbackLogger) Errorf(format string, v ...interface{}) {
	cl.ErrorDepth(1, fmt.Sprintf(format, v...))
}

// Printf is part of the Logger interface.
func (cl *CallbackLogger) Printf(format string, v ...interface{}) {
	file, line := fileAndLine(2)
	cl.f(&logutilpb.Event{
		Time:  TimeToProto(time.Now()),
		Level: logutilpb.Level_CONSOLE,
		File:  file,
		Line:  line,
		Value: fmt.Sprintf(format, v...),
	})
}

// ChannelLogger is a Logger that sends the logging events through a channel for
// consumption.
type ChannelLogger struct {
	CallbackLogger
	C chan *logutilpb.Event
}

// NewChannelLogger returns a CallbackLogger which will write the data
// on a channel
func NewChannelLogger(size int) *ChannelLogger {
	c := make(chan *logutilpb.Event, size)
	return &ChannelLogger{
		CallbackLogger: CallbackLogger{
			f: func(e *logutilpb.Event) {
				c <- e
			},
		},
		C: c,
	}
}

// MemoryLogger keeps the logging events in memory.
// All protected by a mutex.
type MemoryLogger struct {
	CallbackLogger

	// mu protects the Events
	mu     sync.Mutex
	Events []*logutilpb.Event
}

// NewMemoryLogger returns a new MemoryLogger
func NewMemoryLogger() *MemoryLogger {
	ml := &MemoryLogger{}
	ml.CallbackLogger.f = func(e *logutilpb.Event) {
		ml.mu.Lock()
		defer ml.mu.Unlock()
		ml.Events = append(ml.Events, e)
	}
	return ml
}

// String returns all the lines in one String, separated by '\n'
func (ml *MemoryLogger) String() string {
	buf := new(bytes.Buffer)
	ml.mu.Lock()
	defer ml.mu.Unlock()
	for _, event := range ml.Events {
		EventToBuffer(event, buf)
		buf.WriteByte('\n')
	}
	return buf.String()
}

// Clear clears the logs.
func (ml *MemoryLogger) Clear() {
	ml.mu.Lock()
	ml.Events = nil
	ml.mu.Unlock()
}

// LoggerWriter is an adapter that implements the io.Writer interface.
type LoggerWriter struct {
	logger Logger
}

// NewLoggerWriter returns an io.Writer on top of the logger
func NewLoggerWriter(logger Logger) io.Writer {
	return LoggerWriter{
		logger: logger,
	}
}

// Write implements io.Writer
func (lw LoggerWriter) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	lw.logger.Printf("%v", string(p))
	return len(p), nil
}

// TeeLogger is a Logger that sends its logs to two underlying logger
type TeeLogger struct {
	One, Two Logger
}

// NewTeeLogger returns a logger that sends its logs to both loggers
func NewTeeLogger(one, two Logger) *TeeLogger {
	return &TeeLogger{
		One: one,
		Two: two,
	}
}

// InfoDepth is part of the Logger interface
func (tl *TeeLogger) InfoDepth(depth int, s string) {
	tl.One.InfoDepth(1+depth, s)
	tl.Two.InfoDepth(1+depth, s)
}

// WarningDepth is part of the Logger interface
func (tl *TeeLogger) WarningDepth(depth int, s string) {
	tl.One.WarningDepth(1+depth, s)
	tl.Two.WarningDepth(1+depth, s)
}

// ErrorDepth is part of the Logger interface
func (tl *TeeLogger) ErrorDepth(depth int, s string) {
	tl.One.ErrorDepth(1+depth, s)
	tl.Two.ErrorDepth(1+depth, s)
}

// Infof is part of the Logger interface
func (tl *TeeLogger) Infof(format string, v ...interface{}) {
	tl.InfoDepth(1, fmt.Sprintf(format, v...))
}

// Warningf is part of the Logger interface
func (tl *TeeLogger) Warningf(format string, v ...interface{}) {
	tl.WarningDepth(1, fmt.Sprintf(format, v...))
}

// Errorf is part of the Logger interface
func (tl *TeeLogger) Errorf(format string, v ...interface{}) {
	tl.ErrorDepth(1, fmt.Sprintf(format, v...))
}

// Printf is part of the Logger interface
func (tl *TeeLogger) Printf(format string, v ...interface{}) {
	tl.One.Printf(format, v...)
	tl.Two.Printf(format, v...)
}

// array for fast int -> string conversion
const digits = "0123456789"

// twoDigits adds a zero-prefixed two-digit integer to buf
func twoDigits(buf *bytes.Buffer, value int) {
	buf.WriteByte(digits[value/10])
	buf.WriteByte(digits[value%10])
}

// nDigits adds an n-digit integer d to buf
// padding with pad on the left.
// It assumes d >= 0.
func nDigits(buf *bytes.Buffer, n, d int, pad byte) {
	tmp := make([]byte, n)
	j := n - 1
	for ; j >= 0 && d > 0; j-- {
		tmp[j] = digits[d%10]
		d /= 10
	}
	for ; j >= 0; j-- {
		tmp[j] = pad
	}
	buf.Write(tmp)
}

// someDigits adds a zero-prefixed variable-width integer to buf
func someDigits(buf *bytes.Buffer, d int64) {
	// Print into the top, then copy down.
	tmp := make([]byte, 10)
	j := 10
	for {
		j--
		tmp[j] = digits[d%10]
		d /= 10
		if d == 0 {
			break
		}
	}
	buf.Write(tmp[j:])
}

// fileAndLine returns the caller's file and line 2 levels above
func fileAndLine(depth int) (string, int64) {
	_, file, line, ok := runtime.Caller(depth)
	if !ok {
		return "???", 1
	}

	slash := strings.LastIndex(file, "/")
	if slash >= 0 {
		file = file[slash+1:]
	}
	return file, int64(line)
}
