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

package main

import (
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/lbmap"
)

// k8sAPIServerSVCBootstrap stores a state when bootstrapping the k8s api-server
// service w/o kube-proxy.
type k8sAPIServerSVCBootstrap struct {
	// Previous URL of k8s api-server which will be restored after the bootstrap.
	// Usually, it is a ClusterIP of k8s api-server SVC.
	prevAPIServerURL string
	// Indicates whether the bootstrap has been successfully finished.
	done bool
}

// initK8sAPIServerSVCBootstrap temporarily changes the API server URL so that
// the k8s client could connect to the api-server. Later on, after we have received
// a Service update for the api-server and created the BPF LB service for it,
// we can restore the URL (done by maybeFinish(), which should be called from
// a handler which receives k8s Service updates).
func initK8sAPIServerSVCBootstrap(apiServerURL string) (*k8sAPIServerSVCBootstrap, error) {
	// Read the existing api-server address which will be restored after
	// the bootstrap has been finished.
	ipAddr := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if ipAddr == "" || port == "" {
		return nil, fmt.Errorf("KUBERNETES_SERVICE_{HOST,PORT} env variable is not set")
	}
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return nil, fmt.Errorf("Invalid KUBERNETES_SERVICE_PORT %s: %s", port, err)
	}

	// Check whether a svc for the api-server already exists. If yes, then there
	// is no need to bootstrap again (happens after cilium-agent has restarted
	// after the successful bootstrap).
	svc := loadbalancer.NewL3n4Addr(loadbalancer.NONE, net.ParseIP(ipAddr), uint16(portNum))
	if lbmap.ExistAndHaveBackends(svc) {
		return &k8sAPIServerSVCBootstrap{done: true}, nil
	}

	log.WithField(logfields.L3n4Addr, svc).
		Infof("Bootstrapping k8s api-server service via %s", apiServerURL)

	// Temporarily set the api-server address.
	k8s.SetAPIServerURL(apiServerURL)

	return &k8sAPIServerSVCBootstrap{
		prevAPIServerURL: "https://" + net.JoinHostPort(ipAddr, port),
		done:             false,
	}, nil
}

func (b *k8sAPIServerSVCBootstrap) maybeFinish(svcFrontendIPAddr net.IP, svcPort uint16, backendCount int) error {
	if b.done {
		// The SVC has been already done, so nothing to do.
		return nil
	}

	if backendCount == 0 {
		// The SVC update didn't contain any backend. Restoring the API Server URL
		// would blackhole all new connections to the api-server.
		return nil
	}

	url := "https://" + net.JoinHostPort(svcFrontendIPAddr.String(), strconv.Itoa(int(svcPort)))
	if url != b.prevAPIServerURL {
		// Bail out if the SVC update wasn't for the api-server.
		return nil
	}

	if err := k8s.UpdateAPIServerURL(b.prevAPIServerURL); err != nil {
		fmt.Errorf("Failed to restore k8s api-server URL: %s", err)
	}

	log.Infof("Finished bootstrapping k8s api-server service")

	b.done = true

	return nil
}
