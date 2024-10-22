// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package mtu

import (
	"context"
	"net"

	"github.com/cilium/hive/cell"
)

func autoDetect() (int, error) {
	return EthernetMTU, nil
}

func getMTUFromIf(net.IP) (int, error) {
	return EthernetMTU, nil
}

func detectRuntimeMTUChange(ctx context.Context, p mtuParams, health cell.Health, runningMTU int) error {
	return nil
}
