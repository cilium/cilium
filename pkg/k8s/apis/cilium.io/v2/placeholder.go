// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2

// +k8s:deepcopy-gen=false
// +deepequal-gen=false

// Unused
// +kubebuilder:pruning:PreserveUnknownFields
type UnusedPlaceholder struct{}

func (*UnusedPlaceholder) MarshalJSON() ([]byte, error) {
	return []byte{}, nil
}

func (*UnusedPlaceholder) UnmarshalJSON(b []byte) error {
	return nil
}

func (in *UnusedPlaceholder) DeepCopyInto(_ *UnusedPlaceholder) {
}

func (in *UnusedPlaceholder) DeepCopy() *UnusedPlaceholder {
	if in == nil {
		return nil
	}
	return &UnusedPlaceholder{}
}

func (*UnusedPlaceholder) DeepEqual(_ *UnusedPlaceholder) bool {
	return true
}

// +k8s:deepcopy-gen=false
// +deepequal-gen=false

// Unused
type UnusedPlaceholders []UnusedPlaceholder

func (*UnusedPlaceholders) MarshalJSON() ([]byte, error) {
	return []byte{}, nil
}

func (*UnusedPlaceholders) UnmarshalJSON(b []byte) error {
	return nil
}

func (*UnusedPlaceholders) DeepCopyInto(_ *UnusedPlaceholders) {
}

func (*UnusedPlaceholders) DeepCopy() *UnusedPlaceholders {
	return nil
}

func (*UnusedPlaceholders) DeepEqual(_ *UnusedPlaceholders) bool {
	return true
}

// +k8s:deepcopy-gen=false
// +deepequal-gen=false

// Unused
type UnusedPlaceholderString string

func (*UnusedPlaceholderString) MarshalJSON() ([]byte, error) {
	return []byte{}, nil
}

func (*UnusedPlaceholderString) UnmarshalJSON(b []byte) error {
	return nil
}

func (in *UnusedPlaceholderString) DeepCopyInto(_ *UnusedPlaceholderString) {
}

func (in *UnusedPlaceholderString) DeepCopy() *UnusedPlaceholderString {
	if in == nil {
		return nil
	}
	return new(UnusedPlaceholderString)
}

func (*UnusedPlaceholderString) DeepEqual(_ *UnusedPlaceholderString) bool {
	return true
}
