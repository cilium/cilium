// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tables"
)

var _ sysctl.Sysctl = (*Sysctl)(nil)

type Sysctl struct{}

func (sysctl *Sysctl) Disable(name string) error {
	return nil
}

func (sysctl *Sysctl) DisableN(name []string) error {
	return nil
}

func (sysctl *Sysctl) Enable(name string) error {
	return nil
}

func (sysctl *Sysctl) EnableN(name []string) error {
	return nil
}

func (sysctl *Sysctl) Write(name string, val string) error {
	return nil
}

func (sysctl *Sysctl) WriteN(name []string, val string) error {
	return nil
}

func (sysctl *Sysctl) WriteInt(name string, val int64) error {
	return nil
}

func (sysctl *Sysctl) WriteIntN(name []string, val int64) error {
	return nil
}

func (sysctl *Sysctl) ApplySettings(sysSettings []tables.Sysctl) error {
	return nil
}

func (sysctl *Sysctl) Read(name string) (string, error) {
	return "", nil
}

func (sysctl *Sysctl) ReadN(name []string) (string, error) {
	return "", nil
}

func (sysctl *Sysctl) ReadInt(name string) (int64, error) {
	return int64(0), nil
}

func (sysctl *Sysctl) ReadIntN(name []string) (int64, error) {
	return int64(0), nil
}
