// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sysctl

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	subsystem = "sysctl"

	procFsDefault = "/proc"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, subsystem)

	// parameterElemRx matches an element of a sysctl parameter.
	parameterElemRx = regexp.MustCompile(`\A[-0-9_a-z]+\z`)

	procFsMU lock.Mutex
	// procFsRead is mark as true if procFs changes value.
	procFsRead bool
	procFs     = procFsDefault
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

	// Warn if non-empty is the alternative warning log message to use when IgnoreErr is false.
	Warn string
}

// parameterPath returns the path to the sysctl file for parameter name.
func parameterPath(name string) (string, error) {
	elems := strings.Split(name, ".")
	for _, elem := range elems {
		if !parameterElemRx.MatchString(elem) {
			return "", ErrInvalidSysctlParameter(name)
		}
	}
	return filepath.Join(append([]string{GetProcfs(), "sys"}, elems...)...), nil
}

// SetProcfs sets path for the root's /proc. Calling it after GetProcfs causes
// panic.
func SetProcfs(path string) {
	procFsMU.Lock()
	defer procFsMU.Unlock()
	if procFsRead {
		// do not change the procfs after we have gotten its value from GetProcfs
		panic("SetProcfs called after GetProcfs")
	}
	procFs = path
}

// GetProcfs returns the path set in procFs. Executing SetProcFs after GetProcfs
// might panic depending. See SetProcfs for more info.
func GetProcfs() string {
	procFsMU.Lock()
	defer procFsMU.Unlock()
	procFsRead = true
	return procFs
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

// WriteInt writes the given integer type sysctl parameter.
func WriteInt(name string, val int64) error {
	return writeSysctl(name, strconv.FormatInt(val, 10))
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

// ReadInt reads the given sysctl parameter, return an int64 value.
func ReadInt(name string) (int64, error) {
	s, err := Read(name)
	if err != nil {
		return -1, err
	}

	i, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return -1, err
	}

	return i, nil
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

			warn := "Failed to sysctl -w"
			if s.Warn != "" {
				warn = s.Warn
			}
			log.WithError(err).WithFields(logrus.Fields{
				logfields.SysParamName:  s.Name,
				logfields.SysParamValue: s.Val,
			}).Warning(warn)
		}
	}

	return nil
}
