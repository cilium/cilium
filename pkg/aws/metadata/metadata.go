// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metadata

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	smithyhttp "github.com/aws/smithy-go/transport/http"

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

// InterfaceAddresses holds the IPv4 addresses and prefixes of one network interface.
type InterfaceAddresses struct {
	IPv4s        []netip.Addr
	IPv4Prefixes []netip.Prefix
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

// GetInterfaceAddresses returns the IPv4 addresses and prefixes of the interface with the given MAC.
func (m *metadataClient) GetInterfaceAddresses(ctx context.Context, mac string) (InterfaceAddresses, error) {
	var res InterfaceAddresses

	ips, err := getMetadataList(ctx, m.client, fmt.Sprintf("network/interfaces/macs/%s/local-ipv4s", mac))
	if err != nil {
		return InterfaceAddresses{}, err
	}
	for _, ip := range ips {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return InterfaceAddresses{}, fmt.Errorf("unable to parse IPv4 address %q of interface %s: %w", ip, mac, err)
		}
		res.IPv4s = append(res.IPv4s, addr)
	}

	prefixes, err := getMetadataList(ctx, m.client, fmt.Sprintf("network/interfaces/macs/%s/ipv4-prefix", mac))
	if err != nil {
		return InterfaceAddresses{}, err
	}
	for _, p := range prefixes {
		prefix, err := netip.ParsePrefix(p)
		if err != nil {
			return InterfaceAddresses{}, fmt.Errorf("unable to parse IPv4 prefix %q of interface %s: %w", p, mac, err)
		}
		res.IPv4Prefixes = append(res.IPv4Prefixes, prefix)
	}

	return res, nil
}

// getMetadataList returns the entries of a metadata list, or none when the list does not exist.
func getMetadataList(ctx context.Context, client *imds.Client, path string) ([]string, error) {
	value, err := getMetadata(ctx, client, path)
	if respErr, ok := errors.AsType[*smithyhttp.ResponseError](err); ok && respErr.HTTPStatusCode() == http.StatusNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return strings.Fields(value), nil
}
