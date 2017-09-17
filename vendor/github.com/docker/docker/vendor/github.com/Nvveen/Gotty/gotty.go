// Copyright 2012 Neal van Veen. All rights reserved.
// Usage of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Gotty is a Go-package for reading and parsing the terminfo database
package gotty

// TODO add more concurrency to name lookup, look for more opportunities.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path"
	"reflect"
	"strings"
	"sync"
)

// Open a terminfo file by the name given and construct a TermInfo object.
// If something went wrong reading the terminfo database file, an error is
// returned.
func OpenTermInfo(termName string) (*TermInfo, error) {
	if len(termName) == 0 {
		return nil, errors.New("No termname given")
	}
	// Find the environment variables
	if termloc := os.Getenv("TERMINFO"); len(termloc) > 0 {
		return readTermInfo(path.Join(termloc, string(termName[0]), termName))
	} else {
		// Search like ncurses
		locations := []string{}
		if h := os.Getenv("HOME"); len(h) > 0 {
			locations = append(locations, path.Join(h, ".terminfo"))
		}
		locations = append(locations,
			"/etc/terminfo/",
			"/lib/terminfo/",
			"/usr/share/terminfo/")
		for _, str := range locations {
			term, err := readTermInfo(path.Join(str, string(termName[0]), termName))
			if err == nil {
				return term, nil
			}
		}
		return nil, errors.New("No terminfo file(-location) found")
	}
}

// Open a terminfo file from the environment variable containing the current
// terminal name and construct a TermInfo object. If something went wrong
// reading the terminfo database file, an error is returned.
func OpenTermInfoEnv() (*TermInfo, error) {
	termenv := os.Getenv("TERM")
	return OpenTermInfo(termenv)
}

// Return an attribute by the name attr provided. If none can be found,
// an error is returned.
func (term *TermInfo) GetAttribute(attr string) (stacker, error) {
	// Channel to store the main value in.
	var value stacker
	// Add a blocking WaitGroup
	var block sync.WaitGroup
	// Keep track of variable being written.
	written := false
	// Function to put into goroutine.
	f := func(ats interface{}) {
		var ok bool
		var v stacker
		// Switch on type of map to use and assign value to it.
		switch reflect.TypeOf(ats).Elem().Kind() {
		case reflect.Bool:
			v, ok = ats.(map[string]bool)[attr]
		case reflect.Int16:
			v, ok = ats.(map[string]int16)[attr]
		case reflect.String:
			v, ok = ats.(map[string]string)[attr]
		}
		// If ok, a value is found, so we can write.
		if ok {
			value = v
			written = true
		}
		// Goroutine is done
		block.Done()
	}
	block.Add(3)
	// Go for all 3 attribute lists.
	go f(term.boolAttributes)
	go f(term.numAttributes)
	go f(term.strAttributes)
	// Wait until every goroutine is done.
	block.Wait()
	// If a value has been written, return it.
	if written {
		return value, nil
	}
	// Otherwise, error.
	return nil, fmt.Errorf("Erorr finding attribute")
}

// Return an attribute by the name attr provided. If none can be found,
// an error is returned. A name is first converted to its termcap value.
func (term *TermInfo) GetAttributeName(name string) (stacker, error) {
	tc := GetTermcapName(name)
	return term.GetAttribute(tc)
}

// A utility function that finds and returns the termcap equivalent of a
// variable name.
func GetTermcapName(name string) string {
	// Termcap name
	var tc string
	// Blocking group
	var wait sync.WaitGroup
	// Function to put into a goroutine
	f := func(attrs []string) {
		// Find the string corresponding to the name
		for i, s := range attrs {
			if s == name {
				tc = attrs[i+1]
			}
		}
		// Goroutine is finished
		wait.Done()
	}
	wait.Add(3)
	// Go for all 3 attribute lists
	go f(BoolAttr[:])
	go f(NumAttr[:])
	go f(StrAttr[:])
	// Wait until every goroutine is done
	wait.Wait()
	// Return the termcap name
	return tc
}

// This function takes a path to a terminfo file and reads it in binary
// form to construct the actual TermInfo file.
func readTermInfo(path string) (*TermInfo, error) {
	// Open the terminfo file
	file, err := os.Open(path)
	defer file.Close()
	if err != nil {
		return nil, err
	}

	// magic, nameSize, boolSize, nrSNum, nrOffsetsStr, strSize
	// Header is composed of the magic 0432 octal number, size of the name
	// section, size of the boolean section, the amount of number values,
	// the number of offsets of strings, and the size of the string section.
	var header [6]int16
	// Byte array is used to read in byte values
	var byteArray []byte
	// Short array is used to read in short values
	var shArray []int16
	// TermInfo object to store values
	var term TermInfo

	// Read in the header
	err = binary.Read(file, binary.LittleEndian, &header)
	if err != nil {
		return nil, err
	}
	// If magic number isn't there or isn't correct, we have the wrong filetype
	if header[0] != 0432 {
		return nil, errors.New(fmt.Sprintf("Wrong filetype"))
	}

	// Read in the names
	byteArray = make([]byte, header[1])
	err = binary.Read(file, binary.LittleEndian, &byteArray)
	if err != nil {
		return nil, err
	}
	term.Names = strings.Split(string(byteArray), "|")

	// Read in the booleans
	byteArray = make([]byte, header[2])
	err = binary.Read(file, binary.LittleEndian, &byteArray)
	if err != nil {
		return nil, err
	}
	term.boolAttributes = make(map[string]bool)
	for i, b := range byteArray {
		if b == 1 {
			term.boolAttributes[BoolAttr[i*2+1]] = true
		}
	}
	// If the number of bytes read is not even, a byte for alignment is added
	// We know the header is an even number of bytes so only need to check the
	// total of the names and booleans.
	if (header[1]+header[2])%2 != 0 {
		err = binary.Read(file, binary.LittleEndian, make([]byte, 1))
		if err != nil {
			return nil, err
		}
	}

	// Read in shorts
	shArray = make([]int16, header[3])
	err = binary.Read(file, binary.LittleEndian, &shArray)
	if err != nil {
		return nil, err
	}
	term.numAttributes = make(map[string]int16)
	for i, n := range shArray {
		if n != 0377 && n > -1 {
			term.numAttributes[NumAttr[i*2+1]] = n
		}
	}

	// Read the offsets into the short array
	shArray = make([]int16, header[4])
	err = binary.Read(file, binary.LittleEndian, &shArray)
	if err != nil {
		return nil, err
	}
	// Read the actual strings in the byte array
	byteArray = make([]byte, header[5])
	err = binary.Read(file, binary.LittleEndian, &byteArray)
	if err != nil {
		return nil, err
	}
	term.strAttributes = make(map[string]string)
	// We get an offset, and then iterate until the string is null-terminated
	for i, offset := range shArray {
		if offset > -1 {
			if int(offset) >= len(byteArray) {
				return nil, errors.New("array out of bounds reading string section")
			}
			r := bytes.IndexByte(byteArray[offset:], 0)
			if r == -1 {
				return nil, errors.New("missing nul byte reading string section")
			}
			r += int(offset)
			term.strAttributes[StrAttr[i*2+1]] = string(byteArray[offset:r])
		}
	}
	return &term, nil
}
