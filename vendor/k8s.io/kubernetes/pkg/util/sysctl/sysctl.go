/*
Copyright 2015 The Kubernetes Authors.

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

package sysctl

import (
	"io/ioutil"
	"path"
	"strconv"
	"strings"
)

const (
	sysctlBase         = "/proc/sys"
	VmOvercommitMemory = "vm/overcommit_memory"
	VmPanicOnOOM       = "vm/panic_on_oom"
	KernelPanic        = "kernel/panic"
	KernelPanicOnOops  = "kernel/panic_on_oops"
	RootMaxKeys        = "kernel/keys/root_maxkeys"
	RootMaxBytes       = "kernel/keys/root_maxbytes"

	VmOvercommitMemoryAlways    = 1 // kernel performs no memory over-commit handling
	VmPanicOnOOMInvokeOOMKiller = 0 // kernel calls the oom_killer function when OOM occurs

	KernelPanicOnOopsAlways  = 1  // kernel panics on kernel oops
	KernelPanicRebootTimeout = 10 // seconds after a panic for the kernel to reboot

	RootMaxKeysSetting  = 1000000                 // Needed since docker creates a new key per container
	RootMaxBytesSetting = RootMaxKeysSetting * 25 // allocate 25 bytes per key * number of MaxKeys
)

// An injectable interface for running sysctl commands.
type Interface interface {
	// GetSysctl returns the value for the specified sysctl setting
	GetSysctl(sysctl string) (int, error)
	// SetSysctl modifies the specified sysctl flag to the new value
	SetSysctl(sysctl string, newVal int) error
}

// New returns a new Interface for accessing sysctl
func New() Interface {
	return &procSysctl{}
}

// procSysctl implements Interface by reading and writing files under /proc/sys
type procSysctl struct {
}

// GetSysctl returns the value for the specified sysctl setting
func (_ *procSysctl) GetSysctl(sysctl string) (int, error) {
	data, err := ioutil.ReadFile(path.Join(sysctlBase, sysctl))
	if err != nil {
		return -1, err
	}
	val, err := strconv.Atoi(strings.Trim(string(data), " \n"))
	if err != nil {
		return -1, err
	}
	return val, nil
}

// SetSysctl modifies the specified sysctl flag to the new value
func (_ *procSysctl) SetSysctl(sysctl string, newVal int) error {
	return ioutil.WriteFile(path.Join(sysctlBase, sysctl), []byte(strconv.Itoa(newVal)), 0640)
}
