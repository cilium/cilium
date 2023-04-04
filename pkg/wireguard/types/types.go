// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Common Wireguard types and constants
package types

const (
	// IfaceName is the name of the Wireguard tunnel device
	IfaceName = "cilium_wg0"
	// PrivKeyFilename is the name of the Wireguard private key file
	PrivKeyFilename = "cilium_wg0.key"
	// StaticEncryptKey is used in the IPCache to mark entries for which we
	// want to enable Wireguard encryption
	StaticEncryptKey = uint8(0xFF)
)
