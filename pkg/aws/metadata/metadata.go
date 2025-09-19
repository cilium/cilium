// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metadata

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"

	"github.com/cilium/cilium/pkg/safeio"
)

type metadataClient struct {
	client *imds.Client
}

type MetaDataInfo struct {
	InstanceID       string
	InstanceType     string
	AvailabilityZone string
	VPCID            string
	SubnetID         string
}

func NewClient() (*metadataClient, error) {
	client, err := newClient()
	if err != nil {
		return nil, err
	}
	return &metadataClient{client: client}, nil
}

func newClient() (*imds.Client, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, err
	}

	return imds.NewFromConfig(cfg), nil
}

func getMetadata(client *imds.Client, path string) (string, error) {
	res, err := client.GetMetadata(context.TODO(), &imds.GetMetadataInput{
		Path: path,
	})
	if err != nil {
		return "", fmt.Errorf("unable to retrieve AWS metadata %s: %w", path, err)
	}

	defer res.Content.Close()
	value, err := safeio.ReadAllLimit(res.Content, safeio.MB)
	if err != nil {
		return "", fmt.Errorf("unable to read response content for AWS metadata %q: %w", path, err)
	}

	return string(value), err
}

// GetInstanceMetadata returns required AWS metadatas
func (m *metadataClient) GetInstanceMetadata() (MetaDataInfo, error) {

	instanceID, err := getMetadata(m.client, "instance-id")
	if err != nil {
		return MetaDataInfo{}, err
	}

	instanceType, err := getMetadata(m.client, "instance-type")
	if err != nil {
		return MetaDataInfo{}, err
	}

	eth0MAC, err := getMetadata(m.client, "mac")
	if err != nil {
		return MetaDataInfo{}, err
	}
	vpcIDPath := fmt.Sprintf("network/interfaces/macs/%s/vpc-id", eth0MAC)
	vpcID, err := getMetadata(m.client, vpcIDPath)
	if err != nil {
		return MetaDataInfo{}, err
	}

	subnetIDPath := fmt.Sprintf("network/interfaces/macs/%s/subnet-id", eth0MAC)
	subnetID, err := getMetadata(m.client, subnetIDPath)
	if err != nil {
		return MetaDataInfo{}, err
	}

	availabilityZone, err := getMetadata(m.client, "placement/availability-zone")
	if err != nil {
		return MetaDataInfo{}, err
	}

	return MetaDataInfo{
		InstanceID:       instanceID,
		InstanceType:     instanceType,
		AvailabilityZone: availabilityZone,
		VPCID:            vpcID,
		SubnetID:         subnetID,
	}, nil
}
