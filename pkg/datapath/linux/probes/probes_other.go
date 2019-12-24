// Copyright 2019 Authors of Cilium
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

// +build !linux

package probes

// This is a fake replacement of probes_linux.go module which makes it possible
// to build Cilium or run unit tests on other platforms than Linux without
// performing real eBPF feature checks. It has no real use, as Cilium does not
// support any other implementations of BPF then eBPF in the Linux kernel.

// probeManager is a manager of BPF feature checks.
type probeManager struct{}

// NewprobeManager returns a new instance of ProbeManager - a manager of BPF
// feature checks.
func NewProbeManager() (*ProbeManager, error) {
	return &probeManager{}, nil
}

// SystemConfigProbes performs a check of system configuration parameters.
func (p *probeManager) SystemConfigProbes() error {
	return nil
}
