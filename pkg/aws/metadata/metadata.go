// Copyright 2019-21 Authors of Cilium
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
	"strings"
)

func getMetadata(ctx context.Context, name string) (string, error) {
	url := "http://169.254.169.254/latest/meta-data/" + name
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("unable to retrieve instance-id from metadata server: %s", err)
	}

	defer resp.Body.Close()
	metadata, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("unable to read response body: %s", err)
	}

	return string(metadata), nil
}

// GetInstanceMetadata returns the instance ID and type
func GetInstanceMetadata() (instanceID, instanceType, availabilityZone, vpcID string, err error) {
	ctx := context.TODO()

	instanceID, err = getMetadata(ctx, "instance-id")
	if err != nil {
		return
	}

	instanceType, err = getMetadata(ctx, "instance-type")
	if err != nil {
		return
	}

	eth0MAC, err := getMetadata(ctx, "mac")
	if err != nil {
		return
	}

	vpcIDPath := fmt.Sprintf("network/interfaces/macs/%s/vpc-id", eth0MAC)
	vpcID, err = getMetadata(ctx, vpcIDPath)
	if err != nil {
		return
	}

	availabilityZone, err = getMetadata(ctx, "placement/availability-zone")
	return
}

// GetVPCIPv4CIDRBlocks returns the CIDR blocks associated with mac's VPC.
func GetVPCIPv4CIDRBlocks(ctx context.Context, mac string) ([]string, error) {
	name := "network/interfaces/macs/" + string(mac) + "/vpc-ipv4-cidr-blocks"
	metadata, err := getMetadata(ctx, name)
	if err != nil {
		return nil, err
	}
	return strings.Fields(metadata), nil
}
