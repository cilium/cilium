// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type tarWriter interface {
	io.Writer
	WriteHeader(hdr *tar.Header) error
}

type walker struct {
	baseDir, dbgDir string
	output          tarWriter
	log             io.Writer
}

func newWalker(baseDir, dbgDir string, output tarWriter, logger io.Writer) *walker {
	return &walker{
		baseDir: baseDir,
		dbgDir:  dbgDir,
		output:  output,
		log:     logger,
	}
}

func (w *walker) walkPath(path string, info os.FileInfo, err error) error {
	if err != nil {
		fmt.Fprintf(w.log, "Error while walking path %s: %s", path, err)
		return nil
	}
	if info == nil {
		fmt.Fprintf(w.log, "No file info available")
		return nil
	}

	file, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(w.log, "Failed to open %s: %s\n", path, err)
		// TODO: Write an empty file here, just to hint that this file
		// existed by there was some problem attempting to add it.
		return nil
	}
	defer file.Close()

	if info.IsDir() {
		fmt.Fprintf(w.log, "Skipping directory %s\n", info.Name())
		return nil
	}

	// Just get the latest fileInfo to make sure that the size is correctly
	// when the file is write to tar file
	fpInfo, err := file.Stat()
	if err != nil {
		fpInfo, err = os.Lstat(file.Name())
		if err != nil {
			fmt.Fprintf(w.log, "Failed to retrieve file information: %s\n", err)
			return nil
		}
	}

	header, err := tar.FileInfoHeader(fpInfo, fpInfo.Name())
	if err != nil {
		fmt.Fprintf(w.log, "Failed to prepare file info %s: %s\n", fpInfo.Name(), err)
		return nil
	}

	if w.baseDir != "" {
		header.Name = filepath.Join(w.baseDir, strings.TrimPrefix(path, w.dbgDir))
	}

	if err := w.output.WriteHeader(header); err != nil {
		fmt.Fprintf(w.log, "Failed to write header: %s\n", err)
		return nil
	}

	_, err = io.Copy(w.output, file)
	return err
}

func createArchive(dbgDir string, sendArchiveToStdout bool) (string, error) {
	// Based on https://blog.ralch.com/articles/golang-working-with-tar-and-gzip/
	file := os.Stdout
	archivePath := "STDOUT"

	if !sendArchiveToStdout {
		archivePath = fmt.Sprintf("%s.tar", dbgDir)
		var err error
		file, err = os.Create(archivePath)
		if err != nil {
			return "", err
		}
		defer file.Close()
	}

	writer := tar.NewWriter(file)
	defer writer.Close()

	var baseDir string
	if info, err := os.Stat(dbgDir); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Debug directory does not exist %s\n", err)
		return "", err
	} else if err == nil && info.IsDir() {
		baseDir = filepath.Base(dbgDir)
	}

	walker := newWalker(baseDir, dbgDir, writer, os.Stderr)
	return archivePath, filepath.Walk(dbgDir, walker.walkPath)
}

func createGzip(dbgDir string, sendArchiveToStdout bool) (string, error) {
	// Based on https://blog.ralch.com/articles/golang-working-with-tar-and-gzip/
	source, err := createArchive(dbgDir, false)
	if err != nil {
		return "", err
	}

	reader, err := os.Open(source)
	if err != nil {
		return "", err
	}

	writer := os.Stdout
	filename := "STDOUT"
	target := filename

	if !sendArchiveToStdout {
		filename = filepath.Base(source)
		target = fmt.Sprintf("%s.gz", source)
		writer, err = os.Create(target)
		if err != nil {
			return "", err
		}
		defer writer.Close()
	}

	archiver := gzip.NewWriter(writer)
	archiver.Name = filename
	defer archiver.Close()

	_, err = io.Copy(archiver, reader)
	if err != nil {
		return "", err
	}

	return target, nil
}

// Note that `auth-trunc` is also a relevant pattern, but we already match on the more generic
// `auth` pattern.
var isEncryptionKey = regexp.MustCompile("(auth|enc|aead|comp)(.*[[:blank:]](0[xX][[:xdigit:]]+))?")

// hashEncryptionKeys processes the buffer containing the output of `ip -s xfrm state`.
// It searches for IPsec keys in the output and replaces them by their hash.
func hashEncryptionKeys(output []byte) []byte {
	var b bytes.Buffer
	lines := bytes.Split(output, []byte("\n"))
	// Search for lines containing encryption keys.
	for i, line := range lines {
		// isEncryptionKey.FindStringSubmatchIndex(line) will return:
		// - [], if the global pattern is not found
		// - a slice of integers, if the global pattern is found. The
		//   first two integers are the start and end offsets of the
		//   global pattern. The remaining integers are the start and
		//   end offset of each submatch group (delimited in the
		//   regular expressions by parenthesis).
		//
		// If the global pattern is found, the start and end offset of
		// the hexadecimal string (the third submatch) will be at index
		// 6 and 7 in the slice. They may be equal to -1 if the
		// submatch, marked as optional ('?'), is not found.
		matched := isEncryptionKey.FindSubmatchIndex(line)
		if matched != nil && matched[6] > 0 {
			key := line[matched[6]:matched[7]]
			h := sha256.New()
			h.Write(key)
			sum := h.Sum(nil)
			hashedKey := make([]byte, hex.EncodedLen(len(sum)))
			hex.Encode(hashedKey, sum)
			fmt.Fprintf(&b, "%s[hash:%s]%s", line[:matched[6]], hashedKey, line[matched[7]:])
		} else if matched != nil && matched[6] < 0 {
			b.WriteString("[redacted]")
		} else {
			b.Write(line)
		}
		if i < len(lines)-1 {
			b.WriteByte('\n')
		}
	}
	return b.Bytes()
}
