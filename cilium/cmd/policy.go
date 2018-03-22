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
	"regexp"
	"strings"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api/v2"
	"github.com/cilium/cilium/pkg/policy/api/v3"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// policyCmd represents the policy command
var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage security policies",
}

var (
	ignoredMasksSource = []string{".git"}
	ignoredMasks       []*regexp.Regexp
)

func init() {
	ignoredMasks = make([]*regexp.Regexp, len(ignoredMasksSource))

	for i := range ignoredMasksSource {
		ignoredMasks[i] = regexp.MustCompile(ignoredMasksSource[i])
	}

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
	l := ""
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
	for i := range ignoredMasks {
		if ignoredMasks[i].MatchString(name) {
			logrus.WithField(logfields.Path, name).Debug("Ignoring file")
			return true
		}
	}

	return false
}

func loadPolicyFile(path string) (v3.Rules, error) {
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

	var ruleList v3.Rules
	err = json.Unmarshal(content, &ruleList)
	if err == nil {
		err = ruleList.Sanitize()
	}
	if err != nil {
		// try load a v2.Rule
		var v2RuleList v2.Rules
		err2 := json.Unmarshal(content, &v2RuleList)
		if err2 != nil {
			return nil, handleUnmarshalError(path, content, err)
		}
		err = v2RuleList.Sanitize()
		if err != nil {
			return nil, handleUnmarshalError(path, content, err)
		}
		var v3RuleList *v3.Rules
		v3RuleList, err = v3.V2RulesTov3RulesSanitized(&v2RuleList)
		if err != nil {
			return nil, handleUnmarshalError(path, content, err)
		}
		if v3RuleList != nil {
			ruleList = *v3RuleList
		}
	}

	return ruleList, err
}

func loadPolicy(name string) (v3.Rules, error) {
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

	result := v3.Rules{}
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

func processAllFilesFirst(name string, files []os.FileInfo) (v3.Rules, error) {
	result := v3.Rules{}

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

func recursiveSearch(name string, files []os.FileInfo) (v3.Rules, error) {
	result := v3.Rules{}
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
