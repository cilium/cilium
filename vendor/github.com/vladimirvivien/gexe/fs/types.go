package fs

import (
	"io"
	"os"
)

// FileReader aggregates read operations from
// diverse sources into a file
type FileReader interface {
	Err() error
	Info() os.FileInfo
	String() string
	Lines() []string
	Bytes() []byte
	Into(io.Writer) FileReader
}

// FileWriter aggregates several file-writing operations from
// diverse sources into a provided file.
type FileWriter interface {
	Err() error
	Info() os.FileInfo
	String(string) FileWriter
	Lines([]string) FileWriter
	Bytes([]byte) FileWriter
	From(io.Reader) FileWriter
}

// FileAppender is FileWriter with append behavior
type FileAppender interface {
	FileWriter
}
