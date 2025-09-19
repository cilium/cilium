// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metadata

type metadataMock struct {
}

func NewMetadataMock() (*metadataMock, error) {
	return &metadataMock{}, nil
}

// GetInstanceMetadata returns required AWS metadatas
func (m *metadataMock) GetInstanceMetadata() (instanceID, instanceType, availabilityZone, vpcID, subnetID string, err error) {
	return "", "", "", "", "", nil
}
