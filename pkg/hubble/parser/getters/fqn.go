// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package getters

// BlankFQN is an empty FQN.
var BlankFQN FQN

// FQN represents a fully qualified name of a Kubernetes resource.
type FQN struct {
	Namespace, Name string
}

// NewFQN creates a new instance.
func NewFQN(namespace, name string) FQN {
	if namespace == "" && name == "" {
		return BlankFQN
	}

	return FQN{
		Namespace: namespace,
		Name:      name,
	}
}

// IsBlank returns true if the FQN is empty.
func (f FQN) IsBlank() bool {
	return f == BlankFQN
}
