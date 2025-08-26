// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"io"
	"io/fs"
	"os"

	"github.com/cilium/lumberjack/v2"
)

// NewWriterFunc is a io.WriteCloser constructor.
type NewWriterFunc func() (io.WriteCloser, error)

// FileWriterConfig is the configuration for creating a FileWriter.
type FileWriterConfig struct {
	// Filename is the file to write logs to.  Backup log files will be retained
	// in the same directory.  It uses <processname>-lumberjack.log in
	// os.TempDir() if empty.
	Filename string

	// MaxSize is the maximum size in megabytes of the log file before it gets
	// rotated. It defaults to 100 megabytes.
	MaxSize int

	// MaxAge is the maximum number of days to retain old log files based on the
	// timestamp encoded in their filename.  Note that a day is defined as 24
	// hours and may not exactly correspond to calendar days due to daylight
	// savings, leap seconds, etc. The default is not to remove old log files
	// based on age.
	MaxAge int

	// MaxBackups is the maximum number of old log files to retain.  The default
	// is to retain all old log files (though MaxAge may still cause them to get
	// deleted.)
	MaxBackups int

	// LocalTime determines if the time used for formatting the timestamps in
	// backup files is the computer's local time.  The default is to use UTC
	// time.
	LocalTime bool

	// Compress determines if the rotated log files should be compressed
	// using gzip. The default is not to perform compression.
	Compress bool

	// FileMode is the file's mode and permission bits of the log file. If set
	// it will be used as the specified mode.
	FileMode fs.FileMode
}

// FileWriter is a NewWriterFunc that returns an io.WriteCloser for a file with advanced
// capabilities such as automatic file rotation and compression.
func FileWriter(config FileWriterConfig) func() (io.WriteCloser, error) {
	return func() (io.WriteCloser, error) {
		return &lumberjack.Logger{
			Filename:   config.Filename,
			MaxSize:    config.MaxSize,
			MaxBackups: config.MaxBackups,
			Compress:   config.Compress,
		}, nil
	}
}

// StdoutNoOpWriter is a NewWriterFunc that returns an io.WriteCloser for Stdout with a no-op Close
// method.
func StdoutNoOpWriter() (io.WriteCloser, error) {
	return &noopWriteCloser{os.Stdout}, nil
}

var _ io.WriteCloser = (*noopWriteCloser)(nil)

type noopWriteCloser struct {
	w io.Writer
}

func (nwc *noopWriteCloser) Write(p []byte) (int, error) {
	return nwc.w.Write(p)
}

func (nwc *noopWriteCloser) Close() error {
	return nil
}
