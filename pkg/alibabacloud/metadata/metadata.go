// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metadata

import (
	"context"
	"fmt"
	"net/http"

	"github.com/cilium/cilium/pkg/safeio"
	"github.com/cilium/cilium/pkg/time"
)

const (
	metadataURL = "http://100.100.100.200/latest/meta-data"
	tokenURL    = "http://100.100.100.200/latest/api/token"

	// tokenTTLSeconds is the token lifetime to request; 21600s (6h) is the
	// maximum the metadata service accepts.
	tokenTTLSeconds = "21600"
	tokenTTLHeader  = "X-aliyun-ecs-metadata-token-ttl-seconds"
	tokenHeader     = "X-aliyun-ecs-metadata-token"
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

// getToken obtains a token for security-hardened instance metadata access.
// Hardened instances reject token-less requests with a 403; normal-mode
// instances accept a token too. It returns an empty string (not an error) when
// a token cannot be obtained, so callers fall back to a token-less request.
func getToken(ctx context.Context, client *http.Client) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, tokenURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set(tokenTTLHeader, tokenTTLSeconds)

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}
	respBytes, err := safeio.ReadAllLimit(resp.Body, safeio.MB)
	if err != nil {
		return ""
	}
	return string(respBytes)
}

// getMetadata reads a value from the instance metadata service.
// See https://www.alibabacloud.com/help/en/ecs/user-guide/view-instance-metadata/
func getMetadata(ctx context.Context, path string) (string, error) {
	client := &http.Client{
		Timeout: time.Second * 10,
	}

	// Attach a token so reads succeed on security-hardened instances; an empty
	// token falls back to a token-less request.
	token := getToken(ctx, client)

	url := fmt.Sprintf("%s/%s", metadataURL, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	if token != "" {
		req.Header.Set(tokenHeader, token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata service returned status code %d", resp.StatusCode)
	}
	respBytes, err := safeio.ReadAllLimit(resp.Body, safeio.MB)
	if err != nil {
		return "", err
	}

	return string(respBytes), nil
}
