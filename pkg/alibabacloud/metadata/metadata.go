// Copyright 2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package metadata

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
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

// GetCIDRBlock returns the IPv4 CIDR that belongs to the ECS instance from metadata
func GetCIDRBlock(ctx context.Context) (string, error) {
	return getMetadata(ctx, "vswitch-cidr-block")
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
	defer resp.Body.Close()
	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(respBytes), nil
}
