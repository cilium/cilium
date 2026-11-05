// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metadata

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"

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

func NewClient(ctx context.Context) (*metadataClient, error) {
	client, err := newClient(ctx)
	if err != nil {
		return nil, err
	}
	return &metadataClient{client: client}, nil
}

func newClient(ctx context.Context) (*imds.Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}

	return imds.NewFromConfig(cfg), nil
}

func getMetadata(ctx context.Context, client *imds.Client, path string) (string, error) {
	res, err := client.GetMetadata(ctx, &imds.GetMetadataInput{
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
func (m *metadataClient) GetInstanceMetadata(ctx context.Context) (MetaDataInfo, error) {

	instanceID, err := getMetadata(ctx, m.client, "instance-id")
	if err != nil {
		return MetaDataInfo{}, err
	}

	instanceType, err := getMetadata(ctx, m.client, "instance-type")
	if err != nil {
		return MetaDataInfo{}, err
	}

	eth0MAC, err := getMetadata(ctx, m.client, "mac")
	if err != nil {
		return MetaDataInfo{}, err
	}
	vpcIDPath := fmt.Sprintf("network/interfaces/macs/%s/vpc-id", eth0MAC)
	vpcID, err := getMetadata(ctx, m.client, vpcIDPath)
	if err != nil {
		return MetaDataInfo{}, err
	}

	subnetIDPath := fmt.Sprintf("network/interfaces/macs/%s/subnet-id", eth0MAC)
	subnetID, err := getMetadata(ctx, m.client, subnetIDPath)
	if err != nil {
		return MetaDataInfo{}, err
	}

	availabilityZone, err := getMetadata(ctx, m.client, "placement/availability-zone")
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

// GetVPCIPv4CIDRs returns the IPv4 CIDRs associated with the VPC the instance
// belongs to, as reported by the IMDS.
//
// The returned slice has the VPC's primary CIDR as its first element, followed
// by the secondary CIDR associations sorted in a deterministic order.
func (m *metadataClient) GetVPCIPv4CIDRs(ctx context.Context) ([]netip.Prefix, error) {
	mac, err := getMetadata(ctx, m.client, "mac")
	if err != nil {
		return nil, err
	}

	primaryRaw, err := getMetadata(ctx, m.client, fmt.Sprintf("network/interfaces/macs/%s/vpc-ipv4-cidr-block", mac))
	if err != nil {
		return nil, err
	}

	allRaw, err := getMetadata(ctx, m.client, fmt.Sprintf("network/interfaces/macs/%s/vpc-ipv4-cidr-blocks", mac))
	if err != nil {
		return nil, err
	}

	return parseVPCIPv4CIDRs(primaryRaw, allRaw)
}

// parseVPCIPv4CIDRs turns the raw vpc-ipv4-cidr-block and vpc-ipv4-cidr-blocks
// IMDS responses into the ordered prefix list documented on GetVPCIPv4CIDRs.
func parseVPCIPv4CIDRs(primaryRaw, allRaw string) ([]netip.Prefix, error) {
	primary, err := netip.ParsePrefix(strings.TrimSpace(primaryRaw))
	if err != nil {
		return nil, fmt.Errorf("unable to parse VPC primary IPv4 CIDR %q: %w", primaryRaw, err)
	}
	primary = primary.Masked()

	// The response is newline-separated and includes the primary CIDR. It is
	// dropped here to be prepended after the secondary CIDRs have been sorted.
	fields := strings.Fields(allRaw)
	secondary := make([]netip.Prefix, 0, len(fields))
	for _, field := range fields {
		prefix, err := netip.ParsePrefix(field)
		if err != nil {
			return nil, fmt.Errorf("unable to parse VPC IPv4 CIDR %q: %w", field, err)
		}
		if prefix := prefix.Masked(); prefix != primary {
			secondary = append(secondary, prefix)
		}
	}

	// Ensure secondary CIDRs are sorted for determinism
	slices.SortFunc(secondary, netip.Prefix.Compare)

	return append([]netip.Prefix{primary}, secondary...), nil
}
