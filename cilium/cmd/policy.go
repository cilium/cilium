// Copyright 2017 Authors of Cilium
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
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// policyCmd represents the policy command
var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage security policies",
}

var (
	ignoredFileNames = []string{
		".git",
	}
)

func init() {
	rootCmd.AddCommand(policyCmd)
}

func getContext(content []byte, offset int64) (int, string, int) {
	if offset >= int64(len(content)) || offset < 0 {
		return 0, fmt.Sprintf("[error: Offset %d is out of bounds 0..%d]", offset, len(content)), 0
	}

	lineN := strings.Count(string(content[:offset]), "\n") + 1

	start := strings.LastIndexByte(string(content[:offset]), '\n')
	if start == -1 {
		start = 0
	} else {
		start++
	}

	end := strings.IndexByte(string(content[start:]), '\n')
	var l string
	if end == -1 {
		l = string(content[start:])
	} else {
		end = end + start
		l = string(content[start:end])
	}

	return lineN, l, (int(offset) - start)
}

func handleUnmarshalError(f string, content []byte, err error) error {
	switch e := err.(type) {
	case *json.SyntaxError:
		line, ctx, off := getContext(content, e.Offset)

		if off <= 1 {
			return fmt.Errorf("malformed policy, not JSON?")
		}

		preoff := off - 1
		pre := make([]byte, preoff)
		copy(pre, ctx[:preoff])
		for i := 0; i < preoff && i < len(pre); i++ {
			if pre[i] != '\t' {
				pre[i] = ' '
			}
		}

		return fmt.Errorf("%s:%d: syntax error at offset %d:\n%s\n%s^",
			path.Base(f), line, off, ctx, pre)
	case *json.UnmarshalTypeError:
		line, ctx, off := getContext(content, e.Offset)
		return fmt.Errorf("%s:%d: unable to assign value '%s' to type '%v':\n%s\n%*c",
			path.Base(f), line, e.Value, e.Type, ctx, off, '^')
	default:
		return fmt.Errorf("%s: unknown error:%s", path.Base(f), err)
	}
}

func ignoredFile(name string) bool {
	for _, n := range ignoredFileNames {
		if name == n {
			logrus.WithField(logfields.Path, name).Debug("Ignoring file")
			return true
		}
	}

	return false
}

func loadPolicyFile(path string) (api.Rules, error) {
	var content []byte
	var err error
	logrus.WithField(logfields.Path, path).Debug("Loading file")

	if path == "-" {
		content, err = ioutil.ReadAll(bufio.NewReader(os.Stdin))
	} else {
		content, err = ioutil.ReadFile(path)
	}

	if err != nil {
		return nil, err
	}

	var ruleList api.Rules
	err = json.Unmarshal(content, &ruleList)
	if err != nil {
		return nil, handleUnmarshalError(path, content, err)
	}

	return ruleList, nil
}

func loadPolicy(name string) (api.Rules, error) {
	logrus.WithField(logfields.Path, name).Debug("Entering directory")

	if name == "-" {
		return loadPolicyFile(name)
	}

	if fi, err := os.Stat(name); err != nil {
		return nil, err
	} else if fi.Mode().IsRegular() {
		return loadPolicyFile(name)
	} else if !fi.Mode().IsDir() {
		return nil, fmt.Errorf("Error: %s is not a file or a directory", name)
	}

	files, err := ioutil.ReadDir(name)
	if err != nil {
		return nil, err
	}

	result := api.Rules{}
	ruleList, err := processAllFilesFirst(name, files)
	if err != nil {
		return nil, err
	}
	result = append(result, ruleList...)

	ruleList, err = recursiveSearch(name, files)
	if err != nil {
		return nil, err
	}
	result = append(result, ruleList...)

	logrus.WithField(logfields.Path, name).Debug("Leaving directory")

	return result, nil
}

func processAllFilesFirst(name string, files []os.FileInfo) (api.Rules, error) {
	result := api.Rules{}

	for _, f := range files {
		if f.IsDir() || ignoredFile(path.Base(f.Name())) {
			continue
		}

		ruleList, err := loadPolicyFile(filepath.Join(name, f.Name()))
		if err != nil {
			return nil, err
		}

		result = append(result, ruleList...)
	}

	return result, nil
}

func recursiveSearch(name string, files []os.FileInfo) (api.Rules, error) {
	result := api.Rules{}
	for _, f := range files {
		if f.IsDir() {
			if ignoredFile(path.Base(f.Name())) {
				continue
			}
			subpath := filepath.Join(name, f.Name())
			ruleList, err := loadPolicy(subpath)
			if err != nil {
				return nil, err
			}
			result = append(result, ruleList...)
		}
	}
	return result, nil
}
