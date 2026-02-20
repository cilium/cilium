// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strings"
)

// A rootDirCheck checks that Cilium is checked out in path. Environment
// variables in path are expanded with os.ExpandEnv.
type rootDirCheck struct {
	rootDir string
}

func (c rootDirCheck) Name() string {
	return "root-dir"
}

func (c rootDirCheck) Run() (checkResult, string) {
	dir, err := os.Getwd()
	if err != nil {
		return checkError, fmt.Sprintf("cannot get working directory: %s", err)
	}

	// Search upward through through parent directories to find the .git directory.
	for {
		gitRootPath := path.Join(dir, ".git")
		info, err := os.Stat(gitRootPath)

		switch {
		case err == nil && isGitRoot(gitRootPath, info):
			if dir != os.ExpandEnv(c.rootDir) {
				foundDir := dir
				if strings.HasPrefix(dir, goPath()+"/") {
					foundDir = "$GOPATH/" + dir[len(goPath())+1:]
				}
				return checkWarning, fmt.Sprintf("found %s, want %s", foundDir, c.rootDir)
			}
			return checkOK, fmt.Sprintf("found %s", c.rootDir)
		case err == nil:
			// .git exists in dir but is not a directory, continue searching upward.
		case errors.Is(err, fs.ErrNotExist):
			// .git does not exist in dir, continue searching upward.
		default:
			return checkError, fmt.Sprintf("stat %s: %v", dir, err)
		}

		if dir == "/" {
			return checkError, "could not find root directory"
		}
		dir = path.Dir(dir)
	}
}

func (c rootDirCheck) Hint() string {
	return fmt.Sprintf("run git clone https://github.com/cilium/cilium.git %s && cd %s", c.rootDir, c.rootDir)
}

func isGitRoot(path string, info os.FileInfo) bool {
	if info.IsDir() {
		return true
	}

	// Is this a git worktree?
	data, err := os.ReadFile(path)
	return err == nil && strings.HasPrefix(string(data), "gitdir:")
}
