// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"context"
	"errors"
	"fmt"

	awsMetadata "github.com/cilium/cilium/pkg/aws/metadata"
	"github.com/cilium/cilium/pkg/lock"
)

type metadataClient interface {
	GetInstanceMetadata(ctx context.Context) (awsMetadata.MetaDataInfo, error)
}

// instanceMetadata owns the EC2 IMDS client of the agent, and fetches the
// metadata of the instance the agent runs on once and remembers it.
type instanceMetadata struct {
	mu     lock.Mutex
	newFn  func(ctx context.Context) (metadataClient, error)
	client metadataClient
	info   *awsMetadata.MetaDataInfo
}

// newInstanceMetadata is deliberately free of side effects: the aws-agent cell
// runs in every agent, whatever the configured IPAM mode, so the IMDS client is
// only created by the first get.
func newInstanceMetadata() *instanceMetadata {
	return &instanceMetadata{
		newFn: func(ctx context.Context) (metadataClient, error) {
			return awsMetadata.NewClient(ctx)
		},
	}
}

// get returns the metadata of the EC2 instance the agent runs on.
func (m *instanceMetadata) get(ctx context.Context) (awsMetadata.MetaDataInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.info != nil {
		return *m.info, nil
	}

	if m.client == nil {
		client, err := m.newFn(ctx)
		if err != nil {
			return awsMetadata.MetaDataInfo{}, fmt.Errorf("unable to create EC2 metadata client: %w", err)
		}
		m.client = client
	}

	info, err := m.client.GetInstanceMetadata(ctx)
	if err != nil {
		return awsMetadata.MetaDataInfo{}, fmt.Errorf("unable to retrieve InstanceID of own EC2 instance: %w", err)
	}
	if info.InstanceID == "" {
		return awsMetadata.MetaDataInfo{}, errors.New("InstanceID of own EC2 instance is empty")
	}

	m.info = &info
	return info, nil
}
