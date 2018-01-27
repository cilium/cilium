// Copyright 2017-2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func createArchive(dbgDir string) (string, error) {
	// Based on http://blog.ralch.com/tutorial/golang-working-with-tar-and-gzip/
	archivePath := fmt.Sprintf("%s.tar", dbgDir)
	file, err := os.Create(archivePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	writer := tar.NewWriter(file)
	defer writer.Close()

	var baseDir string
	if info, err := os.Stat(dbgDir); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Debug directory does not exist %s", err)
		return "", err
	} else if err == nil && info.IsDir() {
		baseDir = filepath.Base(dbgDir)
	}

	return archivePath, filepath.Walk(dbgDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		header, err := tar.FileInfoHeader(info, info.Name())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to compress %s %s", info.Name(), err)
			return err
		}

		if baseDir != "" {
			header.Name = filepath.Join(baseDir, strings.TrimPrefix(path, dbgDir))
		}

		if err := writer.WriteHeader(header); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write header %s", err)
			return err
		}

		if info.IsDir() {
			return err
		}

		file, err := os.Open(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open %s %s", path, err)
		}
		defer file.Close()
		_, err = io.Copy(writer, file)
		return err
	})
}
