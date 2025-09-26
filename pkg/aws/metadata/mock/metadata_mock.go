// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mock

import "github.com/cilium/cilium/pkg/aws/metadata"

type metadataMock struct {
}

func NewMetadataMock() (*metadataMock, error) {
	return &metadataMock{}, nil
}

// GetInstanceMetadata returns required AWS metadatas
func (m *metadataMock) GetInstanceMetadata() (metadata.MetaDataInfo, error) {
	return metadata.MetaDataInfo{}, nil
}
