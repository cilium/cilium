// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

type Config struct{}

// LocalClusterName returns the name of the cluster Cilium is deployed in
func (f *Config) LocalClusterName() string {
	return "default"
}

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

// NodeEncryptionEnabled returns true if node encryption is enabled
func (f *Config) NodeEncryptionEnabled() bool {
	return true
}

// LocalClusterID returns a dummy cluster ID.
func (f *Config) LocalClusterID() uint32 {
	return 5
}
