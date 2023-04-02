// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/fqdn/re"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/safeio"
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

	// Initialize LRU here because the policy subcommands (validate, import)
	// will call down to sanitizing the FQDN rules which contains regexes.
	// Regexes need to be compiled as part of the FQDN rule validation.
	//
	// It's not necessary to pass a useful size here because it's not
	// necessary to cache regexes in a short-lived binary (CLI).
	re.InitRegexCompileLRU(1)
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
	var r io.Reader
	logrus.WithField(logfields.Path, path).Debug("Loading file")

	if path == "-" {
		r = bufio.NewReader(os.Stdin)
	} else {
		fr, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer fr.Close()
		r = fr
	}
	content, err = safeio.ReadAllLimit(r, safeio.MB)
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

	files, err := os.ReadDir(name)
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

func processAllFilesFirst(name string, files []os.DirEntry) (api.Rules, error) {
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

func recursiveSearch(name string, files []os.DirEntry) (api.Rules, error) {
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
