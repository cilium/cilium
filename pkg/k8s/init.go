// Copyright 2016-2017 Authors of Cilium
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

// Package k8s abstracts all Kubernetes specific behaviour
package k8s

import (
	"fmt"
	"os"

	"github.com/cilium/cilium/pkg/node"

	log "github.com/sirupsen/logrus"
)

// Init initializes the Kubernetes package. It is required to call Configure()
// beforehand.
func Init() error {
	if err := createDefaultClient(); err != nil {
		return fmt.Errorf("unable to create k8s client: %s", err)
	}

	if nodeName := os.Getenv(EnvNodeNameSpec); nodeName != "" {
		// Use of the environment variable overwrites the node-name
		// automatically derived
		node.SetName(nodeName)

		k8sNode, err := GetNode(Client(), nodeName)
		if err != nil {
			return fmt.Errorf("unable to retrieve k8s node information: %s", err)
		}

		n := ParseNode(k8sNode)
		log.Infof("Retrieved node's %s information from kubernetes", n.Name)

		if err := node.UseNodeCIDR(n); err != nil {
			return fmt.Errorf("unable to retrieve k8s node CIDR: %s", err)
		}

		if err := node.UseNodeAddresses(n); err != nil {
			return fmt.Errorf("unable to use k8s node addresses: %s", err)
		}

		// Annotate addresses will occur later since the user might
		// want to specify them manually
	}

	return nil
}
