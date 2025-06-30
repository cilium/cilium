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
func GetInstanceMetadata() (instanceID, instanceType, availabilityZone, vpcID, subnetID string, err error) {
	client, err := newClient()
	if err != nil {
		return
	}

	instanceID, err = getMetadata(client, "instance-id")
	if err != nil {
		return
	}

	instanceType, err = getMetadata(client, "instance-type")
	if err != nil {
		return
	}

	eth0MAC, err := getMetadata(client, "mac")
	if err != nil {
		return
	}
	vpcIDPath := fmt.Sprintf("network/interfaces/macs/%s/vpc-id", eth0MAC)
	vpcID, err = getMetadata(client, vpcIDPath)
	if err != nil {
		return
	}

	subnetIDPath := fmt.Sprintf("network/interfaces/macs/%s/subnet-id", eth0MAC)
	subnetID, err = getMetadata(client, subnetIDPath)
	if err != nil {
		return
	}

	availabilityZone, err = getMetadata(client, "placement/availability-zone")
	if err != nil {
		return
	}

	return
}
