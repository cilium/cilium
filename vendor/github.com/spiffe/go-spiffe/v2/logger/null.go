package logger

// Null is a no-op logger. It is used to suppress logging and is the default
// logger for the library.
var Null Logger = nullLogger{}

type nullLogger struct{}

func (nullLogger) Debugf(format string, args ...interface{}) {}
func (nullLogger) Infof(format string, args ...interface{})  {}
func (nullLogger) Warnf(format string, args ...interface{})  {}
func (nullLogger) Errorf(format string, args ...interface{}) {}
