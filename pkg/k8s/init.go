// Copyright 2016-2018 Authors of Cilium
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
	"time"

	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"

	go_version "github.com/hashicorp/go-version"
	"github.com/sirupsen/logrus"
)

const (
	nodeRetrievalMaxRetries = 15
)

func waitForNodeInformation(nodeName string) *node.Node {
	backoff := backoff.Exponential{
		Min:    time.Duration(200) * time.Millisecond,
		Factor: 2.0,
		Name:   "k8s-node-retrieval",
	}

	for retry := 0; retry < nodeRetrievalMaxRetries; retry++ {
		n, err := retrieveNodeInformation(nodeName)
		if err != nil {
			log.WithError(err).Warning("Waiting for k8s node information")
			backoff.Wait()
			continue
		}

		return n
	}

	return nil
}

func retrieveNodeInformation(nodeName string) (*node.Node, error) {
	requireIPv4CIDR := option.Config.K8sRequireIPv4PodCIDR
	requireIPv6CIDR := option.Config.K8sRequireIPv6PodCIDR

	k8sNode, err := GetNode(Client(), nodeName)
	if err != nil {
		// If no CIDR is required, retrieving the node information is
		// optional
		if !requireIPv4CIDR && !requireIPv6CIDR {
			return nil, nil
		}

		return nil, fmt.Errorf("unable to retrieve k8s node information: %s", err)

	}

	n := ParseNode(k8sNode)
	log.WithField(logfields.NodeName, n.Name).Info("Retrieved node information from kubernetes")

	if requireIPv4CIDR && n.IPv4AllocCIDR == nil {
		return nil, fmt.Errorf("Required IPv4 pod CIDR not present in node resource")
	}

	if requireIPv6CIDR && n.IPv6AllocCIDR == nil {
		return nil, fmt.Errorf("Required IPv6 pod CIDR not present in node resource")
	}

	return n, nil
}

// Init initializes the Kubernetes package. It is required to call Configure()
// beforehand.
func Init() error {
	compatibleVersions, err := go_version.NewConstraint(compatibleK8sVersions)
	if err != nil {
		return fmt.Errorf("unable to parse compatible k8s verions: %s", err)
	}

	if err := createDefaultClient(); err != nil {
		return fmt.Errorf("unable to create k8s client: %s", err)
	}

	sv, err := GetServerVersion()
	if err != nil {
		return fmt.Errorf("k8s client failed to talk to k8s api-server: %s", err)
	}
	if !compatibleVersions.Check(sv) {
		return fmt.Errorf("k8s version (%v) is not in compatible range (%v)", sv, compatibleK8sVersions)
	}

	if nodeName := os.Getenv(EnvNodeNameSpec); nodeName != "" {
		// Use of the environment variable overwrites the node-name
		// automatically derived
		node.SetName(nodeName)

		if n := waitForNodeInformation(nodeName); n != nil {
			log.WithFields(logrus.Fields{
				logfields.NodeName:         n.Name,
				logfields.IPAddr + ".ipv4": n.GetNodeIP(false),
				logfields.IPAddr + ".ipv6": n.GetNodeIP(true),
			}).Info("Received own node information from API server")

			if err := node.UseNodeCIDR(n); err != nil {
				return fmt.Errorf("unable to use k8s node CIDRs: %s", err)
			}

			if err := node.UseNodeAddresses(n); err != nil {
				return fmt.Errorf("unable to use k8s node addresses: %s", err)
			}
		} else {
			// if node resource could not be received, fail if
			// PodCIDR requirement has been requested
			if option.Config.K8sRequireIPv4PodCIDR || option.Config.K8sRequireIPv6PodCIDR {
				log.Fatal("Unable to derive PodCIDR from Kubernetes node resource, giving up")
			}
		}

		// Annotate addresses will occur later since the user might
		// want to specify them manually
	} else if option.Config.K8sRequireIPv4PodCIDR || option.Config.K8sRequireIPv6PodCIDR {
		return fmt.Errorf("node name must be specified via environment variable '%s' to retrieve Kubernetes PodCIDR range", EnvNodeNameSpec)
	}

	return nil
}
