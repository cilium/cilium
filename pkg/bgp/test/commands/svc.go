// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package commands

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/hive/script"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
)

// SvcScriptCmds returns script commands for manipulating services in tests.
func SvcScriptCmds(w *writer.Writer) map[string]script.Cmd {
	return map[string]script.Cmd{
		"svc/set-proxy-redirect": SvcSetProxyRedirectCmd(w),
	}
}

// SvcSetProxyRedirectCmd sets ProxyRedirect on a service, simulating that the
// local Envoy proxy is configured to handle traffic for this service.
// This is used to test BGP advertisement of Gateway API/Ingress services.
func SvcSetProxyRedirectCmd(w *writer.Writer) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Set ProxyRedirect on a service to simulate local Envoy proxy",
			Args:    "namespace/name [proxy-port]",
			Detail: []string{
				"Sets ProxyRedirect on the specified service, indicating that the local",
				"Envoy proxy is configured to handle traffic for this service.",
				"",
				"This simulates the behavior of CiliumEnvoyConfig reconciler when Envoy",
				"is running locally. Used for testing BGP advertisement of Gateway API",
				"and Ingress services.",
				"",
				"The proxy-port argument is optional (default: 10000).",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) < 1 {
				return nil, fmt.Errorf("usage: svc/set-proxy-redirect namespace/name [proxy-port]")
			}

			parts := strings.Split(args[0], "/")
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid service name format %q, expected namespace/name", args[0])
			}
			namespace, name := parts[0], parts[1]

			proxyPort := uint16(10000)
			if len(args) > 1 {
				port, err := strconv.ParseUint(args[1], 10, 16)
				if err != nil {
					return nil, fmt.Errorf("invalid proxy port %q: %w", args[1], err)
				}
				proxyPort = uint16(port)
			}

			return func(*script.State) (stdout, stderr string, err error) {
				svcName := loadbalancer.NewServiceName(namespace, name)

				wtxn := w.WriteTxn()
				defer wtxn.Abort()

				// Get and update the service
				svc, _, found := w.Services().Get(wtxn, loadbalancer.ServiceByName(svcName))
				if !found {
					return "", "", fmt.Errorf("service %s not found", svcName)
				}

				// Clone and set ProxyRedirect
				svc = svc.Clone()
				svc.ProxyRedirect = &loadbalancer.ProxyRedirect{
					ProxyPort: proxyPort,
					Ports:     []uint16{80, 443},
				}

				// UpsertService also calls updateServiceReferences internally,
				// which updates all frontends to point to the new service.
				if _, err := w.UpsertService(wtxn, svc); err != nil {
					return "", "", fmt.Errorf("failed to upsert service: %w", err)
				}

				wtxn.Commit()
				return fmt.Sprintf("Set ProxyRedirect (port=%d) on service %s\n", proxyPort, svcName), "", nil
			}, nil
		},
	)
}
