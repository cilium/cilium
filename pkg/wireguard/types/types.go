// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Common WireGuard types and constants
package types

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
