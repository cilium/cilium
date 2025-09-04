// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package wal

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"fmt"
	"io"
	"iter"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/lock"
)

type Event interface {
	encoding.BinaryMarshaler
}

// Read reads all events from the WAL at logPath using the provided unmarshaller function.
func Read[T Event](logPath string, unmarshaller func(data []byte) (T, error)) (iter.Seq2[T, error], error) {
	file, err := os.OpenFile(logPath, os.O_RDONLY, 0600)
	if err != nil {
		return nil, err
	}

	r := &lvReader{r: file}
	return func(yield func(T, error) bool) {
		defer file.Close()

		for data := range r.Events() {
			e, err := unmarshaller(data)
			if !yield(e, err) {
				return
			}
		}
	}, nil
}

type Writer[T Event] struct {
	logPath string

	mu  lock.Mutex
	log *os.File
}

// NewWriter creates a new WAL writer for events of type T at the specified logPath.
// The log file is created if it does not exist, and truncated if it does.
func NewWriter[T Event](logPath string) (*Writer[T], error) {
	w := &Writer[T]{
		logPath: logPath,
	}

	// Open the log file, create it if it doesn't exist, and truncate it to start fresh.
	if log, err := w.open(logPath, true); err != nil {
		return nil, err
	} else {
		w.log = log
	}

	return w, nil
}

func (w *Writer[T]) open(path string, truncate bool) (*os.File, error) {
	flags := os.O_WRONLY | os.O_CREATE | os.O_APPEND
	if truncate {
		flags |= os.O_TRUNC
	}

	log, err := os.OpenFile(path, flags, 0600)
	if err != nil {
		return nil, err
	}

	return log, nil
}

type BatchError struct {
	Index int
	Err   error
}

func (be BatchError) Error() string {
	return strconv.Itoa(be.Index) + ": " + be.Err.Error()
}

type BatchErrors []BatchError

func (be BatchErrors) Error() string {
	var builder strings.Builder
	for i, e := range be {
		if i > 0 {
			builder.WriteString("; ")
		}
		builder.WriteString(e.Error())
	}
	return builder.String()
}

// Write appends an event to the WAL. Data is flushed to disk before returning.
func (w *Writer[T]) Write(e ...T) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.log == nil {
		return fmt.Errorf("wal closed")
	}

	var ba BatchErrors
	for i, e := range e {
		data, err := e.MarshalBinary()
		if err != nil {
			ba = append(ba, BatchError{Index: i, Err: err})
			continue
		}

		lv := &lvWriter{w: w.log}
		if err := lv.Write(data); err != nil {
			ba = append(ba, BatchError{Index: i, Err: err})
			continue
		}
	}

	// Ensure the data is flushed to disk.
	if err := w.log.Sync(); err != nil {
		return err
	}

	if len(ba) > 0 {
		return ba
	}
	return nil
}

// Compact rewrites the WAL to contain only the provided events, removing any redundant or obsolete entries.
func (w *Writer[T]) Compact(all iter.Seq[T]) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Create a new temporary log file.
	tmpPath := w.logPath + ".tmp"
	tmpLog, err := w.open(tmpPath, true)
	if err != nil {
		return err
	}

	// Write all events to the temporary log file.
	lv := &lvWriter{w: tmpLog}
	for e := range all {
		data, err := e.MarshalBinary()
		if err != nil {
			tmpLog.Close()
			os.Remove(tmpLog.Name())
			return err
		}

		if err := lv.Write(data); err != nil {
			tmpLog.Close()
			os.Remove(tmpLog.Name())
			return err
		}
	}

	// Ensure the temporary log file is flushed to disk.
	if err := tmpLog.Sync(); err != nil {
		tmpLog.Close()
		os.Remove(tmpLog.Name())
		return err
	}

	// Close the temporary log file.
	if err := tmpLog.Close(); err != nil {
		os.Remove(tmpLog.Name())
		return err
	}

	// Close the current log file.
	if err := w.close(); err != nil {
		return err
	}

	// Replace the current log file with the temporary log file.
	if err := os.Rename(tmpPath, w.logPath); err != nil {
		return err
	}

	// Re-open the log file for appending.
	log, err := w.open(w.logPath, false)
	if err != nil {
		return err
	}
	w.log = log
	return nil
}

func (w *Writer[T]) close() error {
	var err error
	if w.log != nil {
		err = w.log.Close()
		w.log = nil
	}
	return err
}

func (w *Writer[T]) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.close()
}

// Length-Value writer
type lvWriter struct {
	w io.Writer
}

func (w *lvWriter) Write(e []byte) error {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(len(e)))
	n, err := w.w.Write(buf[:])
	if err != nil {
		return err
	}
	if n != len(buf) {
		return io.ErrShortWrite
	}

	_, err = io.Copy(w.w, bytes.NewReader(e))
	return err
}

// Length-Value reader
type lvReader struct {
	r io.Reader
}

func (r *lvReader) Events() iter.Seq[[]byte] {
	return func(yield func([]byte) bool) {
		for {
			var buf [8]byte
			n, err := r.r.Read(buf[:])
			if err != nil {
				return
			}
			if n != len(buf) {
				return
			}

			dataLen := int(binary.LittleEndian.Uint64(buf[:]))
			if dataLen == 0 {
				if !yield([]byte{}) {
					return
				}
				continue
			}

			dataBuf := make([]byte, dataLen)
			var read int
			for {
				n, err = r.r.Read(dataBuf[read:])
				if err != nil {
					if err == io.EOF {
						break
					}
					return
				}
				if n == 0 {
					return
				}
				read += n
				if read >= dataLen {
					break
				}
			}
			if !yield(dataBuf) {
				return
			}
		}
	}
}
