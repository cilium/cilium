// Copyright 2020 Authors of Cilium
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

package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	metadataURL = "http://169.254.169.254/metadata"
	// current version of the metadata/instance service
	metadataAPIVersion = "2019-06-01"
)

// GetSubscriptionID retrieves the Azure subscriptionID from the Azure Instance Metadata Service
func GetSubscriptionID(ctx context.Context) (string, error) {
	return getMetadataString(ctx, "instance/compute/subscriptionId")
}

// GetResourceGroupName retrieves the current resource group name in which the host running the Cilium Operator is located
// This is retrieved via the Azure Instance Metadata Service
func GetResourceGroupName(ctx context.Context) (string, error) {
	return getMetadataString(ctx, "instance/compute/resourceGroupName")
}

// getMetadataString returns the text representation of a field from the Azure IMS (instance metadata service)
// more can be found at https://docs.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service#instance-api
func getMetadataString(ctx context.Context, path string) (string, error) {
	client := &http.Client{
		Timeout: time.Second * 10,
	}
	url := fmt.Sprintf("%s/%s", metadataURL, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", nil
	}

	query := req.URL.Query()
	query.Add("api-version", metadataAPIVersion)
	query.Add("format", "text")

	req.URL.RawQuery = query.Encode()
	req.Header.Add("Metadata", "true")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.WithError(err).Errorf("Failed to close body for request %s", url)
		}
	}()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(respBytes), nil
}
