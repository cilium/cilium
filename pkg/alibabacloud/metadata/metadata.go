// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metadata

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/cilium/cilium/pkg/safeio"
)

const (
	metadataURL = "http://100.100.100.200/latest/meta-data"
)

// GetInstanceID returns the instance ID from metadata
func GetInstanceID(ctx context.Context) (string, error) {
	return getMetadata(ctx, "instance-id")
}

// GetInstanceType returns the instance type from metadata
func GetInstanceType(ctx context.Context) (string, error) {
	return getMetadata(ctx, "instance/instance-type")
}

// GetRegionID returns the region ID from metadata
func GetRegionID(ctx context.Context) (string, error) {
	return getMetadata(ctx, "region-id")
}

// GetZoneID returns the zone ID from metadata
func GetZoneID(ctx context.Context) (string, error) {
	return getMetadata(ctx, "zone-id")
}

// GetVPCID returns the vpc ID that belongs to the ECS instance from metadata
func GetVPCID(ctx context.Context) (string, error) {
	return getMetadata(ctx, "vpc-id")
}

// GetVPCCIDRBlock returns the IPv4 CIDR block of the VPC to which the instance belongs
func GetVPCCIDRBlock(ctx context.Context) (string, error) {
	return getMetadata(ctx, "vpc-cidr-block")
}

// getMetadata gets metadata
// see https://www.alibabacloud.com/help/doc-detail/49122.htm
func getMetadata(ctx context.Context, path string) (string, error) {
	client := &http.Client{
		Timeout: time.Second * 10,
	}
	url := fmt.Sprintf("%s/%s", metadataURL, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata service returned status code %d", resp.StatusCode)
	}

	defer resp.Body.Close()
	respBytes, err := safeio.ReadAllLimit(resp.Body, safeio.MB)
	if err != nil {
		return "", err
	}

	return string(respBytes), nil
}
