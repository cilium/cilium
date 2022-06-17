package fs

import (
	"bufio"
	"bytes"
	"io"
	"os"
)

type fileReader struct {
	err   error
	path  string
	finfo os.FileInfo
}

// Read creates a FileReader using the provided path.
// A non-nil FileReader.Err() is returned if file does not exist
// or another error is generated.
func Read(path string) FileReader {
	fr := &fileReader{path: path}
	info, err := os.Stat(fr.path)
	if err != nil {
		fr.err = err
		return fr
	}
	fr.finfo = info
	return fr
}

// Err returns an operation error during file read.
func (fr *fileReader) Err() error {
	return fr.err
}

// Info surfaces the os.FileInfo for the associated file
func (fr *fileReader) Info() os.FileInfo {
	return fr.finfo
}

// String returns the content of the file as a string value
func (fr *fileReader) String() string {
	file, err := os.Open(fr.path)
	if err != nil {
		fr.err = err
		return ""
	}
	defer file.Close()

	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(file); err != nil {
		fr.err = err
		return ""
	}

	return buf.String()
}

// Lines returns the content of the file as slice of string
func (fr *fileReader) Lines() []string {
	file, err := os.Open(fr.path)
	if err != nil {
		fr.err = err
		return []string{}
	}
	var lines []string
	scnr := bufio.NewScanner(file)

	for scnr.Scan() {
		lines = append(lines, scnr.Text())
	}

	if scnr.Err() != nil {
		fr.err = scnr.Err()
		return []string{}
	}

	return lines
}

// Bytes returns the content of the file as []byte
func (fr *fileReader) Bytes() []byte {
	file, err := os.Open(fr.path)
	if err != nil {
		fr.err = err
		return []byte{}
	}
	defer file.Close()

	buf := new(bytes.Buffer)

	if _, err := buf.ReadFrom(file); err != nil {
		fr.err = err
		return []byte{}
	}

	return buf.Bytes()
}

// Into reads the content of the file and writes
// it into the specified Writer
func (fr *fileReader) Into(w io.Writer) FileReader {
	file, err := os.Open(fr.path)
	if err != nil {
		fr.err = err
		return fr
	}
	defer file.Close()
	if _, err := io.Copy(w, file); err != nil {
		fr.err = err
	}
	return fr
}
