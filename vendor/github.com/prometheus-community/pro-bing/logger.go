package probing

import "log"

type Logger interface {
	Fatalf(format string, v ...interface{})
	Errorf(format string, v ...interface{})
	Warnf(format string, v ...interface{})
	Infof(format string, v ...interface{})
	Debugf(format string, v ...interface{})
}

type StdLogger struct {
	Logger *log.Logger
}

func (l StdLogger) Fatalf(format string, v ...interface{}) {
	l.Logger.Printf("FATAL: "+format, v...)
}

func (l StdLogger) Errorf(format string, v ...interface{}) {
	l.Logger.Printf("ERROR: "+format, v...)
}

func (l StdLogger) Warnf(format string, v ...interface{}) {
	l.Logger.Printf("WARN: "+format, v...)
}

func (l StdLogger) Infof(format string, v ...interface{}) {
	l.Logger.Printf("INFO: "+format, v...)
}

func (l StdLogger) Debugf(format string, v ...interface{}) {
	l.Logger.Printf("DEBUG: "+format, v...)
}

type NoopLogger struct {
}

func (l NoopLogger) Fatalf(format string, v ...interface{}) {
}

func (l NoopLogger) Errorf(format string, v ...interface{}) {
}

func (l NoopLogger) Warnf(format string, v ...interface{}) {
}

func (l NoopLogger) Infof(format string, v ...interface{}) {
}

func (l NoopLogger) Debugf(format string, v ...interface{}) {
}
