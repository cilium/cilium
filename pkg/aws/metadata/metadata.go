// Copyright 2019-2021 Authors of Cilium
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
	"io"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
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
	value, err := io.ReadAll(res.Content)
	if err != nil {
		return "", fmt.Errorf("unable to read response content for AWS metadata %q: %w", path, err)
	}

	return string(value), err
}

// GetInstanceMetadata returns required AWS metadatas
func GetInstanceMetadata() (instanceID, instanceType, availabilityZone, vpcID string, err error) {
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

	availabilityZone, err = getMetadata(client, "placement/availability-zone")
	if err != nil {
		return
	}

	return
}
