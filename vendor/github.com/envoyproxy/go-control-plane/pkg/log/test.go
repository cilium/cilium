package log

import "testing"

type testLogger struct {
	t testing.TB
}

var _ Logger = testLogger{}

func NewTestLogger(t testing.TB) Logger {
	return testLogger{t}
}

// Debugf logs a message at level debug on the test logger.
func (l testLogger) Debugf(msg string, args ...interface{}) {
	l.t.Helper()
	l.t.Logf("[debug] "+msg, args...)
}

// Infof logs a message at level info on the test logger.
func (l testLogger) Infof(msg string, args ...interface{}) {
	l.t.Helper()
	l.t.Logf("[info] "+msg, args...)
}

// Warnf logs a message at level warn on the test logger.
func (l testLogger) Warnf(msg string, args ...interface{}) {
	l.t.Helper()
	l.t.Logf("[warn] "+msg, args...)
}

// Errorf logs a message at level error on the test logger.
func (l testLogger) Errorf(msg string, args ...interface{}) {
	l.t.Helper()
	l.t.Logf("[error] "+msg, args...)
}
