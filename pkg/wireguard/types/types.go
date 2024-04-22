// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Common Wireguard types and constants
package types

const (
	// ListenPort is the port on which the WireGuard tunnel device listens on
	ListenPort = 51871
	// IfaceName is the name of the Wireguard tunnel device
	IfaceName = "cilium_wg0"
	// PrivKeyFilename is the name of the Wireguard private key file
	PrivKeyFilename = "cilium_wg0.key"
)
