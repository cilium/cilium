// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1

// GetHostIP returns the Host IP of the pod.
func (p *Pod) GetHostIP() string {
	return p.Status.HostIP
}

// GetAPIVersion returns the API Version for the pod.
func (p *Pod) GetAPIVersion() string {
	return SchemeGroupVersion.Version
}

// GetKind returns its Kind.
func (p *Pod) GetKind() string {
	return "Pod"
}

// IsNil returns true if this structure is nil.
func (p *Pod) IsNil() bool {
	return p == nil
}
