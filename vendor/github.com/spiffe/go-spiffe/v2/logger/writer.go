package logger

import (
	"fmt"
	"io"
)

// Writer provides a logger that outputs logging to the given writer.
func Writer(w io.Writer) Logger {
	return writer{Writer: w}
}

type writer struct {
	io.Writer
}

func (w writer) Debugf(format string, args ...interface{}) {
	fmt.Fprintf(w.Writer, "[DEBUG] "+format+"\n", args...)
}

func (w writer) Infof(format string, args ...interface{}) {
	fmt.Fprintf(w.Writer, "[INFO] "+format+"\n", args...)
}

func (w writer) Warnf(format string, args ...interface{}) {
	fmt.Fprintf(w.Writer, "[WARN] "+format+"\n", args...)
}

func (w writer) Errorf(format string, args ...interface{}) {
	fmt.Fprintf(w.Writer, "[ERROR] "+format+"\n", args...)
}
