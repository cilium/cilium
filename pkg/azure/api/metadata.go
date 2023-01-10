// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/cilium/cilium/pkg/safeio"
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

// GetAzureCloudName retrieves the current Azure cloud name in which the host running the Cilium Operator is located
// This is retrieved via the Azure Instance Metadata Service
func GetAzureCloudName(ctx context.Context) (string, error) {
	return getMetadataString(ctx, "instance/compute/azEnvironment")
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

	respBytes, err := safeio.ReadAllLimit(resp.Body, safeio.MB)
	if err != nil {
		return "", err
	}

	return string(respBytes), nil
}
