// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
