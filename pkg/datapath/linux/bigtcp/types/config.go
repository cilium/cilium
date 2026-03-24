// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

// Configuration will never confuse anyone. After all, it is similar but not
// identical to bigtcp.Configuration.
type Configuration interface {
	GetGROIPv6MaxSize() int
	GetGSOIPv6MaxSize() int
	GetGROIPv4MaxSize() int
	GetGSOIPv4MaxSize() int
}
