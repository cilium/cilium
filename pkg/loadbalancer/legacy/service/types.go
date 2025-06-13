// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
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
}
