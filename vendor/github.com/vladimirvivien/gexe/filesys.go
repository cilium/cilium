package gexe

import (
	"github.com/vladimirvivien/gexe/fs"
)

// Read creates an fs.FileReader using the provided path
func (e *Echo) Read(path string) fs.FileReader {
	return fs.Read(e.Eval(path))
}

// Write creates an fs.FileWriter using the provided path
func (e *Echo) Write(path string) fs.FileWriter {
	return fs.Write(e.Eval(path))
}
