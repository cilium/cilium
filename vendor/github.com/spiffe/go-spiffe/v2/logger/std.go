package logger

import "log"

// Std is a logger that uses the Go standard log library.
var Std Logger = stdLogger{}

type stdLogger struct{}

func (stdLogger) Debugf(format string, args ...interface{}) {
	log.Printf("[DEBUG] "+format+"\n", args...)
}

func (stdLogger) Infof(format string, args ...interface{}) {
	log.Printf("[INFO] "+format+"\n", args...)
}

func (stdLogger) Warnf(format string, args ...interface{}) {
	log.Printf("[WARN] "+format+"\n", args...)
}

func (stdLogger) Errorf(format string, args ...interface{}) {
	log.Printf("[ERROR] "+format+"\n", args...)
}
