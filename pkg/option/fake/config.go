// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

type Config struct{}

// CiliumNamespaceName returns the name of the namespace in which Cilium is
// deployed in
func (f *Config) CiliumNamespaceName() string {
	return "kube-system"
}

// TunnelingEnabled returns true if the tunneling is used.
func (f *Config) TunnelingEnabled() bool {
	return true
}

// RemoteNodeIdentitiesEnabled returns true if the remote-node identity feature
// is enabled
func (f *Config) RemoteNodeIdentitiesEnabled() bool {
	return true
}

// EncryptionEnabled returns true if encryption is enabled
func (f *Config) EncryptionEnabled() bool {
	return true
}

// NodeIpsetNeeded returns true if masquerading rules require entries to be
// added to an ipset for this node
func (f *Config) NodeIpsetNeeded() bool {
	return false
}

// NodeEncryptionEnabled returns true if node encryption is enabled
func (f *Config) NodeEncryptionEnabled() bool {
	return true
}

// IsLocalRouterIP checks if provided IP address matches either LocalRouterIPv4
// or LocalRouterIPv6
func (f *Config) IsLocalRouterIP(ip string) bool {
	return false
}
