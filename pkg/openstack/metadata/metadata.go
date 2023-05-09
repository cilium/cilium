// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metadata

import (
	"context"
	"encoding/json"
	"github.com/cilium/cilium/pkg/safeio"
	"net/http"
)

const (
	metadataURL = "http://169.254.169.254/openstack/latest/meta_data.json"
)

type NodeInfo struct {
	UUID             string `json:"uuid"`
	Hostname         string `json:"hostname"`
	ProjectID        string `json:"project_id"`
	Name             string `json:"name"`
	AvailabilityZone string `json:"availability_zone"`
}

// GetMetadata gets metadata
func GetMetadata(ctx context.Context) (*NodeInfo, error) {

	resp, err := http.Get(metadataURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := safeio.ReadAllLimit(resp.Body, safeio.MB)
	if err != nil {
		return nil, err
	}

	node := &NodeInfo{}
	err = json.Unmarshal(body, node)
	if err != nil {
		return nil, err
	}

	return node, nil
}
