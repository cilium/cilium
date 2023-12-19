// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sysctl

import (
	"errors"
	"strconv"
	"testing"

	"github.com/spf13/afero"

	"github.com/cilium/cilium/pkg/datapath/tables"
)

// NewTestSysctl returns an implementation of Sysctl for privileged tests or benchmarks
// that require to actually change kernel sysctl parameters but don't rely on the
// hive and cells framework. Because those tests don't start a hive, the stateDB plus
// generic reconciler approach cannot be used.
func NewTestSysctl(tb testing.TB) Sysctl {
	return &sysctlTB{tb}
}

type sysctlTB struct {
	t testing.TB
}

func (s *sysctlTB) Disable(name string) error {
	path, err := ParameterPath("/proc", name)
	if err != nil {
		return err
	}

	return WriteSysctl(afero.NewOsFs(), path, "0")
}

func (s *sysctlTB) Enable(name string) error {
	path, err := ParameterPath("/proc", name)
	if err != nil {
		return err
	}

	return WriteSysctl(afero.NewOsFs(), path, "1")
}

func (s *sysctlTB) Write(name string, val string) error {
	path, err := ParameterPath("/proc", name)
	if err != nil {
		return err
	}

	return WriteSysctl(afero.NewOsFs(), path, val)
}

func (s *sysctlTB) WriteInt(name string, val int64) error {
	path, err := ParameterPath("/proc", name)
	if err != nil {
		return err
	}

	return WriteSysctl(afero.NewOsFs(), path, strconv.FormatInt(val, 10))
}

func (s *sysctlTB) ApplySettings(sysSettings []tables.Sysctl) error {
	var errs []error
	for _, setting := range sysSettings {
		errs = append(errs, s.Write(setting.Name, setting.Val))
	}
	return errors.Join(errs...)
}

func (s *sysctlTB) Read(name string) (string, error) {
	path, err := ParameterPath("/proc", name)
	if err != nil {
		return "", err
	}

	return ReadSysctl(afero.NewOsFs(), path)
}

func (s *sysctlTB) ReadInt(name string) (int64, error) {
	path, err := ParameterPath("/proc", name)
	if err != nil {
		return -1, err
	}

	val, err := ReadSysctl(afero.NewOsFs(), path)
	if err != nil {
		return -1, err
	}

	return strconv.ParseInt(val, 10, 64)
}
