// Copyright 2019-2021 Authors of Cilium
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

package sysctl

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
)

const (
	subsystem = "sysctl"

	prefixDir = "/proc/sys"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, subsystem)

	// parameterElemRx matches an element of a sysctl parameter.
	parameterElemRx = regexp.MustCompile(`\A[-0-9_a-z]+\z`)
)

// An ErrInvalidSysctlParameter is returned when a parameter is invalid.
type ErrInvalidSysctlParameter string

func (e ErrInvalidSysctlParameter) Error() string {
	return fmt.Sprintf("invalid sysctl parameter: %q", string(e))
}

// Setting represents a sysctl setting. Its purpose it to be able to iterate
// over a slice of settings.
type Setting struct {
	Name      string
	Val       string
	IgnoreErr bool
}

// parameterPath returns the path to the sysctl file for parameter name.
func parameterPath(name string) (string, error) {
	elems := strings.Split(name, ".")
	for _, elem := range elems {
		if !parameterElemRx.MatchString(elem) {
			return "", ErrInvalidSysctlParameter(name)
		}
	}
	return filepath.Join(append([]string{prefixDir}, elems...)...), nil
}

func writeSysctl(name string, value string) error {
	path, err := parameterPath(name)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0644)
	if err != nil {
		return fmt.Errorf("could not open the sysctl file %s: %s",
			path, err)
	}
	defer f.Close()
	if _, err := io.WriteString(f, value); err != nil {
		return fmt.Errorf("could not write to the systctl file %s: %s",
			path, err)
	}
	return nil
}

// Disable disables the given sysctl parameter.
func Disable(name string) error {
	return writeSysctl(name, "0")
}

// Enable enables the given sysctl parameter.
func Enable(name string) error {
	return writeSysctl(name, "1")
}

// Write writes the given sysctl parameter.
func Write(name string, val string) error {
	return writeSysctl(name, val)
}

// Read reads the given sysctl parameter.
func Read(name string) (string, error) {
	path, err := parameterPath(name)
	if err != nil {
		return "", err
	}
	val, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("Failed to read %s: %s", path, err)
	}

	return strings.TrimRight(string(val), "\n"), nil
}

// ApplySettings applies all settings in sysSettings.
func ApplySettings(sysSettings []Setting) error {
	for _, s := range sysSettings {
		log.WithFields(logrus.Fields{
			logfields.SysParamName:  s.Name,
			logfields.SysParamValue: s.Val,
		}).Info("Setting sysctl")
		if err := Write(s.Name, s.Val); err != nil {
			if !s.IgnoreErr || errors.Is(err, ErrInvalidSysctlParameter("")) {
				return fmt.Errorf("Failed to sysctl -w %s=%s: %s", s.Name, s.Val, err)
			}
			log.WithError(err).WithFields(logrus.Fields{
				logfields.SysParamName:  s.Name,
				logfields.SysParamValue: s.Val,
			}).Warning("Failed to sysctl -w")
		}
	}

	return nil
}
