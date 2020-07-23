// Copyright 2017 Authors of Cilium
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

package cmd

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/loadbalancer"

	"github.com/spf13/cobra"
)

var (
	k8sExternalIPs     bool
	k8sNodePort        bool
	k8sHostPort        bool
	k8sLoadBalancer    bool
	k8sTrafficPolicy   string
	k8sClusterInternal bool
	localRedirect      bool
	idU                uint64
	frontend           string
	protocol           string
	backends           []string
)

// serviceUpdateCmd represents the service_update command
var serviceUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update a service",
	Run: func(cmd *cobra.Command, args []string) {
		updateService(cmd, args)
	},
}

func init() {
	serviceCmd.AddCommand(serviceUpdateCmd)
	serviceUpdateCmd.Flags().Uint64VarP(&idU, "id", "", 0, "Identifier")
	serviceUpdateCmd.Flags().BoolVarP(&k8sExternalIPs, "k8s-external", "", false, "Set service as a k8s ExternalIPs")
	serviceUpdateCmd.Flags().BoolVarP(&k8sNodePort, "k8s-node-port", "", false, "Set service as a k8s NodePort")
	serviceUpdateCmd.Flags().BoolVarP(&k8sLoadBalancer, "k8s-load-balancer", "", false, "Set service as a k8s LoadBalancer")
	serviceUpdateCmd.Flags().BoolVarP(&k8sHostPort, "k8s-host-port", "", false, "Set service as a k8s HostPort")
	serviceUpdateCmd.Flags().BoolVarP(&localRedirect, "local-redirect", "", false, "Set service as Local Redirect")
	serviceUpdateCmd.Flags().StringVarP(&k8sTrafficPolicy, "k8s-traffic-policy", "", "Cluster", "Set service with k8s externalTrafficPolicy as {Local,Cluster}")
	serviceUpdateCmd.Flags().BoolVarP(&k8sClusterInternal, "k8s-cluster-internal", "", false, "Set service as cluster-internal for externalTrafficPolicy=Local")
	serviceUpdateCmd.Flags().StringVarP(&frontend, "frontend", "", "", "Frontend address")
	serviceUpdateCmd.Flags().StringVarP(&protocol, "protocol", "", "tcp", "Protocol for service (e.g. TCP, UDP)")
	serviceUpdateCmd.Flags().StringSliceVarP(&backends, "backends", "", []string{}, "Backend address or addresses (<IP:Port>)")
}

func parseAddress(l4Protocol, address string) (ip net.IP, port int, proto string, err error) {
	switch proto = strings.ToLower(l4Protocol); proto {
	case "tcp":
		var tcpAddr *net.TCPAddr
		tcpAddr, err = net.ResolveTCPAddr(proto, address)
		if err != nil {
			return
		}
		ip = tcpAddr.IP
		port = tcpAddr.Port
	case "udp":
		var udpAddr *net.UDPAddr
		udpAddr, err = net.ResolveUDPAddr(proto, address)
		if err != nil {
			return
		}
		ip = udpAddr.IP
		port = udpAddr.Port
	default:
		err = fmt.Errorf("unrecognized protocol %q", l4Protocol)
	}
	return
}

func parseFrontendAddress(l4Protocol, address string) (*models.FrontendAddress, net.IP) {
	ip, port, proto, err := parseAddress(l4Protocol, address)
	if err != nil {
		Fatalf("Unable to parse frontend address: %s\n", err)
	}

	scope := models.FrontendAddressScopeExternal
	if k8sClusterInternal {
		scope = models.FrontendAddressScopeInternal
	}

	return &models.FrontendAddress{
		IP:       ip.String(),
		Port:     uint16(port),
		Protocol: proto,
		Scope:    scope,
	}, ip
}

func boolToInt(set bool) int {
	if set {
		return 1
	}
	return 0
}

func updateService(cmd *cobra.Command, args []string) {
	id := int64(idU)
	fa, faIP := parseFrontendAddress(protocol, frontend)

	var spec *models.ServiceSpec
	svc, err := client.GetServiceID(id)
	switch {
	case err == nil && (svc.Status == nil || svc.Status.Realized == nil):
		Fatalf("Cannot update service %d: empty state", id)

	case err == nil:
		spec = svc.Status.Realized
		fmt.Printf("Updating existing service with id '%v'\n", id)

	default:
		spec = &models.ServiceSpec{ID: id}
		fmt.Printf("Creating new service with id '%v'\n", id)
	}

	// This can happen when we create a new service or when the service returned
	// to us has no flags set
	if spec.Flags == nil {
		spec.Flags = &models.ServiceSpecFlags{}
	}

	if boolToInt(k8sExternalIPs)+boolToInt(k8sNodePort)+boolToInt(k8sHostPort)+boolToInt(k8sLoadBalancer)+boolToInt(localRedirect) > 1 {
		Fatalf("Can only set one of --k8s-external, --k8s-node-port, --k8s-load-balancer, --k8s-host-port, --local-redirect for a service")
	} else if k8sExternalIPs {
		spec.Flags = &models.ServiceSpecFlags{Type: models.ServiceSpecFlagsTypeExternalIPs}
	} else if k8sNodePort {
		spec.Flags = &models.ServiceSpecFlags{Type: models.ServiceSpecFlagsTypeNodePort}
	} else if k8sLoadBalancer {
		spec.Flags = &models.ServiceSpecFlags{Type: models.ServiceSpecFlagsTypeLoadBalancer}
	} else if k8sHostPort {
		spec.Flags = &models.ServiceSpecFlags{Type: models.ServiceSpecFlagsTypeHostPort}
	} else if localRedirect {
		spec.Flags = &models.ServiceSpecFlags{Type: models.ServiceSpecFlagsTypeLocalRedirect}
	} else {
		spec.Flags = &models.ServiceSpecFlags{Type: models.ServiceSpecFlagsTypeClusterIP}
	}

	if strings.ToLower(k8sTrafficPolicy) == "local" {
		spec.Flags.TrafficPolicy = models.ServiceSpecFlagsTrafficPolicyLocal
	} else {
		spec.Flags.TrafficPolicy = models.ServiceSpecFlagsTrafficPolicyCluster
	}

	spec.FrontendAddress = fa

	if len(backends) == 0 {
		fmt.Printf("Reading backend list from stdin...\n")

		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			backends = append(backends, scanner.Text())
		}
	}

	spec.BackendAddresses = nil
	for _, backend := range backends {
		ip, port, proto, err := parseAddress(protocol, backend)
		if err != nil {
			Fatalf("Cannot parse backend address %q: %s", backend, err)
		}
		// Backend ID will be set by the daemon
		be := loadbalancer.NewBackend(0, loadbalancer.L4Type(strings.ToUpper(proto)), ip, uint16(port))

		if be.IsIPv6() && faIP.To4() != nil {
			Fatalf("Address mismatch between frontend and backend %s", backend)
		}

		if fa.Port == 0 && port != 0 {
			Fatalf("L4 backend found (%s:%d) with L3 frontend", ip, port)
		}

		ba := be.GetBackendModel()
		spec.BackendAddresses = append(spec.BackendAddresses, ba)
	}

	if created, err := client.PutServiceID(id, spec); err != nil {
		Fatalf("Cannot add/update service: %s", err)
	} else if created {
		fmt.Printf("Added service with %d backends\n", len(spec.BackendAddresses))
	} else {
		fmt.Printf("Updated service with %d backends\n", len(spec.BackendAddresses))
	}
}
