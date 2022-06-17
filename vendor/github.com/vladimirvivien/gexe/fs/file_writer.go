package fs

import (
	"io"
	"os"
)

type fileWriter struct {
	path  string
	err   error
	finfo os.FileInfo
	mode  os.FileMode
	flags int
}

// Write creates a new file,or truncates an existing one,
// using the path provided and sets it up for write operations.
// Operation error is returned by FileWriter.Err().
func Write(path string) FileWriter {
	fw := &fileWriter{path: path, flags: os.O_CREATE | os.O_TRUNC | os.O_WRONLY, mode: 0644}
	info, err := os.Stat(fw.path)
	if err == nil {
		fw.finfo = info
	}
	return fw
}

// Append creates a new file, or append to an existing one,
// using the path provided and sets it up for write operation only.
// Any error generated is returned by FileWriter.Err().
func Append(path string) FileWriter {
	fw := &fileWriter{path: path, flags: os.O_CREATE | os.O_APPEND | os.O_WRONLY, mode: 0644}
	info, err := os.Stat(fw.path)
	if err == nil {
		fw.finfo = info
	}

	return fw
}

// Err returns an error during execution
func (fw *fileWriter) Err() error {
	return fw.err
}

// Info returns the os.FileInfo for the associated file
func (fw *fileWriter) Info() os.FileInfo {
	return fw.finfo
}

// String writes the provided str into the file. Any
// error that occurs can be accessed with FileWriter.Err().
func (fw *fileWriter) String(str string) FileWriter {
	file, err := os.OpenFile(fw.path, fw.flags, fw.mode)
	if err != nil {
		fw.err = err
		return fw
	}
	defer file.Close()
	if fw.finfo, fw.err = file.Stat(); fw.err != nil {
		return fw
	}

	if _, err := file.WriteString(str); err != nil {
		fw.err = err
	}
	return fw
}

// Lines writes the slice of strings into the file.
// Any error will be captured and returned via FileWriter.Err().
func (fw *fileWriter) Lines(lines []string) FileWriter {
	file, err := os.OpenFile(fw.path, fw.flags, fw.mode)
	if err != nil {
		fw.err = err
		return fw
	}
	defer file.Close()
	if fw.finfo, fw.err = file.Stat(); fw.err != nil {
		return fw
	}

	len := len(lines)
	for i, line := range lines {
		if _, err := file.WriteString(line); err != nil {
			fw.err = err
			return fw
		}
		if len > (i + 1) {
			if _, err := file.Write([]byte{'\n'}); err != nil {
				fw.err = err
				return fw
			}
		}
	}
	return fw
}

// Bytes writes the []bytre provided into the file.
// Any error can be accessed using FileWriter.Err().
func (fw *fileWriter) Bytes(data []byte) FileWriter {
	file, err := os.OpenFile(fw.path, fw.flags, fw.mode)
	if err != nil {
		fw.err = err
		return fw
	}
	defer file.Close()
	if fw.finfo, fw.err = file.Stat(); fw.err != nil {
		return fw
	}

	if _, err := file.Write(data); err != nil {
		fw.err = err
	}
	return fw
}

// From streams bytes from the provided io.Reader r and
// writes them to the file. Any error will be captured
// and returned by fw.Err().
func (fw *fileWriter) From(r io.Reader) FileWriter {
	file, err := os.OpenFile(fw.path, fw.flags, fw.mode)
	if err != nil {
		fw.err = err
		return fw
	}
	defer file.Close()
	if fw.finfo, fw.err = file.Stat(); fw.err != nil {
		return fw
	}

	if _, err := io.Copy(file, r); err != nil {
		fw.err = err
	}
	return fw
}
