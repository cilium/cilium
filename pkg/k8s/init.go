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
	"context"
	"fmt"
	"os"
	"time"

	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/versioncheck"

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
			backoff.Wait(context.TODO())
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

	n := ParseNode(k8sNode, node.FromAgentLocal)
	log.WithField(logfields.NodeName, n.Name).Info("Retrieved node information from kubernetes")

	if requireIPv4CIDR && n.IPv4AllocCIDR == nil {
		return nil, fmt.Errorf("Required IPv4 pod CIDR not present in node resource")
	}

	if requireIPv6CIDR && n.IPv6AllocCIDR == nil {
		return nil, fmt.Errorf("Required IPv6 pod CIDR not present in node resource")
	}

	return n, nil
}

// useNodeCIDR sets the ipv4-range and ipv6-range values values from the
// addresses defined in the given node.
func useNodeCIDR(n *node.Node) {
	if n.IPv4AllocCIDR != nil && option.Config.EnableIPv4 {
		node.SetIPv4AllocRange(n.IPv4AllocCIDR)
	}
	if n.IPv6AllocCIDR != nil && option.Config.EnableIPv6 {
		if err := node.SetIPv6NodeRange(n.IPv6AllocCIDR.IPNet); err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				logfields.Node:     n.Name,
				logfields.V6Prefix: n.IPv6AllocCIDR,
			}).Warn("k8s: Can't use IPv6 CIDR range from k8s")
		}
	}
}

// Init initializes the Kubernetes package. It is required to call Configure()
// beforehand.
func Init() error {
	compatibleVersions, err := versioncheck.Compile(compatibleK8sVersions)
	if err != nil {
		return fmt.Errorf("unable to parse compatible k8s verions: %s", err)
	}

	if err := createDefaultClient(); err != nil {
		return fmt.Errorf("unable to create k8s client: %s", err)
	}

	if err := createDefaultCiliumClient(); err != nil {
		return fmt.Errorf("unable to create cilium k8s client: %s", err)
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
			nodeIP4 := n.GetNodeIP(false)
			nodeIP6 := n.GetNodeIP(true)

			log.WithFields(logrus.Fields{
				logfields.NodeName:         n.Name,
				logfields.IPAddr + ".ipv4": nodeIP4,
				logfields.IPAddr + ".ipv6": nodeIP6,
				logfields.V4Prefix:         n.IPv4AllocCIDR,
				logfields.V6Prefix:         n.IPv6AllocCIDR,
			}).Info("Received own node information from API server")

			useNodeCIDR(n)

			// Note: Node IPs are derived regardless of
			// option.Config.EnableIPv4 and
			// option.Config.EnableIPv6. This is done to enable
			// underlay addressing to be different from overlay
			// addressing, e.g. an IPv6 only PodCIDR running over
			// IPv4 encapsulation.
			if nodeIP4 != nil {
				node.SetExternalIPv4(nodeIP4)
			}

			if nodeIP6 != nil {
				node.SetIPv6(nodeIP6)
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
