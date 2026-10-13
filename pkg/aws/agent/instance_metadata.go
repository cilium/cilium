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
	GetInterfaceAddresses(ctx context.Context, mac string) (awsMetadata.InterfaceAddresses, error)
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

// clientLocked returns the IMDS client, creating it on first use. The caller holds m.mu.
func (m *instanceMetadata) clientLocked(ctx context.Context) (metadataClient, error) {
	if m.client == nil {
		client, err := m.newFn(ctx)
		if err != nil {
			return nil, fmt.Errorf("unable to create EC2 metadata client: %w", err)
		}
		m.client = client
	}
	return m.client, nil
}

// get returns the metadata of the EC2 instance the agent runs on.
func (m *instanceMetadata) get(ctx context.Context) (awsMetadata.MetaDataInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.info != nil {
		return *m.info, nil
	}

	client, err := m.clientLocked(ctx)
	if err != nil {
		return awsMetadata.MetaDataInfo{}, err
	}

	info, err := client.GetInstanceMetadata(ctx)
	if err != nil {
		return awsMetadata.MetaDataInfo{}, fmt.Errorf("unable to retrieve InstanceID of own EC2 instance: %w", err)
	}
	if info.InstanceID == "" {
		return awsMetadata.MetaDataInfo{}, errors.New("InstanceID of own EC2 instance is empty")
	}

	m.info = &info
	return info, nil
}

// interfaceAddresses returns the IPv4 addresses and prefixes the IMDS lists for an ENI.
func (m *instanceMetadata) interfaceAddresses(ctx context.Context, mac string) (awsMetadata.InterfaceAddresses, error) {
	m.mu.Lock()
	client, err := m.clientLocked(ctx)
	m.mu.Unlock()
	if err != nil {
		return awsMetadata.InterfaceAddresses{}, err
	}

	return client.GetInterfaceAddresses(ctx, mac)
}
