/*
Copyright The ORAS Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ioutil

import (
	"fmt"
	"io"
	"os"
)

// Ingest writes content into a temporary ingest file with the file name format
// "oras_credstore_temp_{randomString}".
func Ingest(dir string, content io.Reader) (path string, ingestErr error) {
	tempFile, err := os.CreateTemp(dir, "oras_credstore_temp_*")
	if err != nil {
		return "", fmt.Errorf("failed to create ingest file: %w", err)
	}
	path = tempFile.Name()
	defer func() {
		if err := tempFile.Close(); err != nil && ingestErr == nil {
			ingestErr = fmt.Errorf("failed to close ingest file: %w", err)
		}
		// remove the temp file in case of error.
		if ingestErr != nil {
			os.Remove(path)
		}
	}()

	if err := tempFile.Chmod(0600); err != nil {
		return "", fmt.Errorf("failed to ensure permission: %w", err)
	}
	if _, err := io.Copy(tempFile, content); err != nil {
		return "", fmt.Errorf("failed to ingest: %w", err)
	}
	return
}
