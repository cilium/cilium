// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package netns

import (
	"fmt"
)

type NetNS struct{}

func New() (*NetNS, error) {
	return nil, fmt.Errorf("not implemented")
}

func OpenPinned(string) (*NetNS, error) {
	return nil, fmt.Errorf("not implemented")
}

func (h *NetNS) FD() int {
	return -1
}

func (h *NetNS) Close() error {
	return fmt.Errorf("not implemented")
}

func (h *NetNS) Do(func() error) error {
	return fmt.Errorf("not implemented")
}
