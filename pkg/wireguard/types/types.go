// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Common WireGuard types and constants
package types

import (
	"github.com/cilium/cilium/api/v1/models"
)

const (
	// ListenPort is the port on which the WireGuard tunnel device listens on
	ListenPort = 51871
	// IfaceName is the name of the WireGuard tunnel device
	IfaceName = "cilium_wg0"
	// PrivKeyFilename is the name of the WireGuard private key file
	PrivKeyFilename = "cilium_wg0.key"
	// StaticEncryptKey is used in the IPCache to mark entries for which we
	// want to enable WireGuard encryption
	StaticEncryptKey = uint8(0xFF)
)

// Agent exports the Enabled and Status commands from the agent.
type Agent interface {
	Enabled() bool
	Status(withPeers bool) (*models.WireguardStatus, error)
	IfaceIndex() (uint32, error)
	IfaceBufferMargins() (uint16, uint16, error)
}

// Config exports the Enabled method rather than the whole config.
// This is useful when the whole agent is not needed. See [Agent] otherwise.
type Config interface {
	Enabled() bool
}
