// Copyright 2019 Authors of Cilium
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
	"fmt"
	"io"
	"net/http"
)

func getMetadata(name string) (string, error) {
	resp, err := http.Get("http://169.254.169.254/latest/meta-data/" + name)
	if err != nil {
		return "", fmt.Errorf("unable to retrieve instance-id from metadata server: %s", err)
	}

	defer resp.Body.Close()
	instanceID, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("unable to read response body: %s", err)
	}

	return string(instanceID), nil
}

// GetInstanceMetadata returns the instance ID and type
func GetInstanceMetadata() (instanceID, instanceType, availabilityZone, vpcID string, err error) {
	instanceID, err = getMetadata("instance-id")
	if err != nil {
		return
	}

	instanceType, err = getMetadata("instance-type")
	if err != nil {
		return
	}

	eth0MAC, err := getMetadata("mac")
	if err != nil {
		return
	}

	vpcIDPath := fmt.Sprintf("network/interfaces/macs/%s/vpc-id", eth0MAC)
	vpcID, err = getMetadata(vpcIDPath)
	if err != nil {
		return
	}

	availabilityZone, err = getMetadata("placement/availability-zone")
	return
}
