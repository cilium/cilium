// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/time"
)

// ServiceManager provides an interface for service related operations.
// It is implemented by service handler which main responsibility is to reflect
// service-related changes into BPF maps used by datapath BPF programs.
type ServiceManager interface {
	// GetCurrentTs retrieves the current timestamp.
	GetCurrentTs() time.Time

	// GetLastUpdatedTs retrieves the last updated timestamp.
	GetLastUpdatedTs() time.Time

	// GetServiceNameByAddr looks up service by IP/port. Hubble uses this function
	// to annotate flows with service information.
	GetServiceNameByAddr(addr lb.L3n4Addr) (string, string, bool)
}
