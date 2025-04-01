//go:build !windows

package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

func adjustDependencies(w io.Writer, baseDir string, deps []dependency) error {
	for _, dep := range deps {
		relativeFile, err := filepath.Rel(baseDir, dep.file)
		if err != nil {
			return err
		}

		if len(dep.prerequisites) == 0 {
			_, err := fmt.Fprintf(w, "%s:\n\n", relativeFile)
			if err != nil {
				return err
			}
			continue
		}

		var prereqs []string
		for _, prereq := range dep.prerequisites {
			relativePrereq, err := filepath.Rel(baseDir, prereq)
			if err != nil {
				return err
			}

			prereqs = append(prereqs, relativePrereq)
		}

		_, err = fmt.Fprintf(w, "%s: \\\n %s\n\n", relativeFile, strings.Join(prereqs, " \\\n "))
		if err != nil {
			return err
		}
	}
	return nil
}

type dependency struct {
	file          string
	prerequisites []string
}

func parseDependencies(baseDir string, in io.Reader) ([]dependency, error) {
	abs := func(path string) string {
		if filepath.IsAbs(path) {
			return path
		}
		return filepath.Join(baseDir, path)
	}

	scanner := bufio.NewScanner(in)
	var line strings.Builder
	var deps []dependency
	for scanner.Scan() {
		buf := scanner.Bytes()
		if line.Len()+len(buf) > 1024*1024 {
			return nil, errors.New("line too long")
		}

		if bytes.HasSuffix(buf, []byte{'\\'}) {
			line.Write(buf[:len(buf)-1])
			continue
		}

		line.Write(buf)
		if line.Len() == 0 {
			// Skip empty lines
			continue
		}

		parts := strings.SplitN(line.String(), ":", 2)
		if len(parts) < 2 {
			return nil, fmt.Errorf("invalid line without ':'")
		}

		// NB: This doesn't handle filenames with spaces in them.
		// It seems like make doesn't do that either, so oh well.
		var prereqs []string
		for _, prereq := range strings.Fields(parts[1]) {
			prereqs = append(prereqs, abs(prereq))
		}

		deps = append(deps, dependency{
			abs(string(parts[0])),
			prereqs,
		})
		line.Reset()
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// There is always at least a dependency for the main file.
	if len(deps) == 0 {
		return nil, fmt.Errorf("empty dependency file")
	}
	return deps, nil
}
