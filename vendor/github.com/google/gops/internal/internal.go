// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package internal

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
)

const gopsConfigDirEnvKey = "GOPS_CONFIG_DIR"

func ConfigDir() (string, error) {
	if configDir := os.Getenv(gopsConfigDirEnvKey); configDir != "" {
		return configDir, nil
	}

	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("APPDATA"), "gops"), nil
	}
	homeDir := guessUnixHomeDir()
	if homeDir == "" {
		return "", errors.New("unable to get current user home directory: os/user lookup failed; $HOME is empty")
	}
	return filepath.Join(homeDir, ".config", "gops"), nil
}

func guessUnixHomeDir() string {
	usr, err := user.Current()
	if err == nil {
		return usr.HomeDir
	}
	return os.Getenv("HOME")
}

func PIDFile(pid int) (string, error) {
	gopsdir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/%d", gopsdir, pid), nil
}

func GetPort(pid int) (string, error) {
	portfile, err := PIDFile(pid)
	if err != nil {
		return "", err
	}
	b, err := ioutil.ReadFile(portfile)
	if err != nil {
		return "", err
	}
	port := strings.TrimSpace(string(b))
	return port, nil
}
