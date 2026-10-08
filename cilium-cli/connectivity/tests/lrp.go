// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/cilium-cli/utils/features"
	"github.com/cilium/cilium/cilium-cli/utils/wait"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/versioncheck"
)

// LRP runs test scenarios for local redirect policy. It tests local redirection
// connectivity from test source pods to LRP frontend.
//
// It tests connectivity with the configured skipRedirectFromBackend flag for:
// - client pods to LRP frontend
// - LRP backend pods to LRP frontend
func LRP(skipRedirectFromBackend bool) check.Scenario {
	return lrp{
		ScenarioBase:            check.NewScenarioBase(),
		skipRedirectFromBackend: skipRedirectFromBackend,
	}
}

type lrp struct {
	check.ScenarioBase
	skipRedirectFromBackend bool
}

func (s lrp) Name() string {
	if s.skipRedirectFromBackend {
		return "lrp-skip-redirect-from-backend"
	}
	return "lrp"
}

func (s lrp) Run(ctx context.Context, t *check.Test) {
	policies := make([]*v2.CiliumLocalRedirectPolicy, 0, len(t.CiliumLocalRedirectPolicies()))

	for _, policy := range t.CiliumLocalRedirectPolicies() {
		spec := policy.Spec
		if spec.RedirectFrontend.AddressMatcher == nil {
			continue
		}
		policies = append(policies, policy)
	}

	t.ForEachIPFamily(func(ipFamily features.IPFamily) {
		// Filter policies by IP family
		var familyPolicies []*v2.CiliumLocalRedirectPolicy
		for _, policy := range policies {
			frontendIP := policy.Spec.RedirectFrontend.AddressMatcher.IP
			if features.GetIPFamily(frontendIP) == ipFamily {
				familyPolicies = append(familyPolicies, policy)
			}
		}

		if len(familyPolicies) == 0 {
			return
		}

		if ipFamily == features.IPFamilyV4 {
			s.runTestsForIPFamily(ctx, t, familyPolicies, ipFamily)
		} else if ipFamily == features.IPFamilyV6 {
			// Split IPv6 policies based on skipRedirectFromBackend
			ipv6SkipTruePolicies := make([]*v2.CiliumLocalRedirectPolicy, 0)
			ipv6SkipFalsePolicies := make([]*v2.CiliumLocalRedirectPolicy, 0)
			for _, policy := range familyPolicies {
				if policy.Spec.SkipRedirectFromBackend {
					ipv6SkipTruePolicies = append(ipv6SkipTruePolicies, policy)
				} else {
					ipv6SkipFalsePolicies = append(ipv6SkipFalsePolicies, policy)
				}
			}

			// Run tests for skipRedirectFromBackend=true policies regardless of SocketLB
			if s.skipRedirectFromBackend && len(ipv6SkipTruePolicies) > 0 {
				if versioncheck.MustCompile(">=1.17.3")(t.Context().CiliumVersion) {
					s.runTestsForIPFamily(ctx, t, ipv6SkipTruePolicies, ipFamily)
				} else {
					t.Info("Skipping IPv6 tests for policies with skipRedirectFromBackend=true. It works with >=1.17.3.")
				}
			}

			// Run tests for skipRedirectFromBackend=false policies only if SocketLB is fully functional
			if !s.skipRedirectFromBackend && len(ipv6SkipFalsePolicies) > 0 {
				if !t.Context().IsSocketLBFull() {
					t.Info("Skipping IPv6 tests for policies with skipRedirectFromBackend=false due to SocketLB not being fully functional")
				} else {
					s.runTestsForIPFamily(ctx, t, ipv6SkipFalsePolicies, ipFamily)
				}
			}
		}
	})
}

func (s lrp) runTestsForIPFamily(ctx context.Context, t *check.Test, policies []*v2.CiliumLocalRedirectPolicy, ipFamily features.IPFamily) {
	ct := t.Context()

	for _, policy := range policies {
		spec := policy.Spec
		frontend := check.NewLRPFrontend(spec.RedirectFrontend)
		frontendStr := net.JoinHostPort(frontend.Address(ipFamily), fmt.Sprint(frontend.Port()))
		if versioncheck.MustCompile(">=1.17.0")(ct.CiliumVersion) {
			frontendStr += fmt.Sprintf("/%s", frontend.Protocol())
		}

		lrpBackendsMap := make(map[string][]string)
		// Check for LRP backend pods deployed on nodes in the cluster.
		for _, pod := range t.Context().LrpBackendPods() {
			node := pod.NodeName()
			podIP := getPodIP(pod, ipFamily)
			if _, ok := lrpBackendsMap[node]; !ok {
				lrpBackendsMap[node] = []string{podIP}
				continue
			}
			lrpBackendsMap[node] = append(lrpBackendsMap[node], podIP)
		}

		// Wait until the local redirect entries are plumbed in the BPF LB map
		// on the cilium agent nodes hosting LRP backend pods.
		WaitForLocalRedirectBPFEntries(ctx, t, frontendStr, lrpBackendsMap)
	}

	// Tests client pods to LRP frontend connectivity: traffic gets redirected
	// to the LRP backends.
	for _, pod := range t.Context().LrpClientPods() {
		for _, policy := range policies {
			if policy.Spec.SkipRedirectFromBackend != s.skipRedirectFromBackend {
				continue
			}

			i := 0
			lf := check.NewLRPFrontend(policy.Spec.RedirectFrontend)
			t.NewAction(s, fmt.Sprintf("curl-%d-%s", i, ipFamily), &pod, lf, ipFamily).Run(func(a *check.Action) {
				a.ExecInPod(ctx, a.CurlCommand(lf))
				i++
			})
		}
	}

	// Tests LRP backend pods to LRP frontend connectivity: traffic gets redirected
	// based on the configured skipRedirectFromBackend flag.
	for _, pod := range t.Context().LrpBackendPods() {
		for _, policy := range policies {
			if policy.Spec.SkipRedirectFromBackend != s.skipRedirectFromBackend {
				continue
			}

			i := 0
			lf := check.NewLRPFrontend(policy.Spec.RedirectFrontend)
			t.NewAction(s, fmt.Sprintf("curl-%d-%s", i, ipFamily), &pod, lf, ipFamily).Run(func(a *check.Action) {
				a.ExecInPod(ctx, a.CurlCommand(lf))

				if policy.Spec.SkipRedirectFromBackend {
					a.ValidateFlows(ctx, pod, a.GetEgressRequirements(check.FlowParameters{
						RSTAllowed: true,
					}))
				}
				i++
			})
		}
	}
}

func getPodIP(pod check.Pod, ipFamily features.IPFamily) string {
	matchesFamily := func(ipStr string) bool {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return false
		}
		if ipFamily == features.IPFamilyV4 {
			return ip.To4() != nil
		}
		return ip.To4() == nil
	}

	if matchesFamily(pod.Pod.Status.PodIP) {
		return pod.Pod.Status.PodIP
	}

	for _, podIP := range pod.Pod.Status.PodIPs {
		if matchesFamily(podIP.IP) {
			return podIP.IP
		}
	}

	return ""
}

func WaitForLocalRedirectBPFEntries(ctx context.Context, t *check.Test, frontend string, backendsMap map[string][]string) {
	ct := t.Context()
	w := wait.NewObserver(ctx, wait.Parameters{Timeout: 20 * time.Second})
	defer w.Cancel()

	ensureBPFLBEntries := func() error {
		cmd := strings.Split("cilium bpf lb list -o json", " ")
		for _, ciliumPod := range ct.CiliumPods() {
			node := ciliumPod.Pod.Spec.NodeName
			backends, ok := backendsMap[node]
			if !ok {
				// No LRP backend pods deployed on this node.
				continue
			}
			stdout, err := ciliumPod.K8sClient.ExecInPod(ctx, ciliumPod.Pod.Namespace, ciliumPod.Pod.Name, defaults.AgentContainerName, cmd)
			if err != nil {
				t.Fatal("Failed to run cilium bpf lb list -o json command:", err)
			}
			var resMap map[string][]string
			err = json.Unmarshal(stdout.Bytes(), &resMap)
			if err != nil {
				return fmt.Errorf("error unmarshalling data: %w", err)
			}
			// An LB mapping (frontend, backend) for example:
			// 169.254.169.255:80 (1)   10.244.1.210:8080 (132) (1)
			parsedLB := make(map[string][]string)
			for frontendEntry, backendEntry := range resMap {
				// strip the space and parentheses
				index := strings.Index(frontendEntry, " ")
				if index > 0 {
					frontendEntry = frontendEntry[:index]
				}
				if len(backendEntry) > 0 {
					parsedLB[frontendEntry] = append(parsedLB[frontendEntry], backendEntry...)
				}
			}
			parsedBes, ok := parsedLB[frontend]
			if !ok {
				return fmt.Errorf("frontend [%s] not found in BPF LB map [%+v]", frontend, parsedLB)
			}
			// Check for frontend and backend mapping in the parsed BPF LB map.
			for _, backend := range backends {
				found := false
				for _, be := range parsedBes {
					if strings.Contains(be, backend) {
						found = true
						break
					}
				}
				if !found {
					return fmt.Errorf("frontend [%s] backend [%s] mapping not found in BPF LB map [%s] %+v", frontend, backend, ciliumPod.Pod.Name, parsedLB)
				}
			}
		}

		return nil
	}

	for {
		if err := ensureBPFLBEntries(); err != nil {
			if err := w.Retry(err); err != nil {
				t.Fatal("Failed to ensure local redirect BPF entries: %w", err)
			}

			continue
		}
		return
	}
}

// LRPWithNodeDNS runs test scenarios for local redirect policy
// with the node local DNS setup.
//
// It sends HTTP requests to the externalEcho service to check
// the DNS requests are resolved by node-local DNS cache pods.
// The network policy allows the clients to access node-local-dns
// and the externalEcho service.
func LRPWithNodeDNS() check.Scenario {
	return lrpWithNodeDNS{
		ScenarioBase: check.NewScenarioBase(),
	}
}

type lrpWithNodeDNS struct {
	check.ScenarioBase
}

func (s lrpWithNodeDNS) Name() string {
	return "local-redirect-policy-with-node-dns"
}

func (s lrpWithNodeDNS) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()

	i := 0
	for _, client := range ct.ClientPods() {
		for _, externalEchoSvc := range ct.EchoExternalServices() {
			externalEcho := externalEchoSvc.ToEchoIPService()

			actionName := fmt.Sprintf("lrp-node-dns-http-to-%s-%d", externalEcho.NameWithoutNamespace(), i)
			t.NewAction(s, actionName, &client, externalEcho, features.IPFamilyV4).Run(func(a *check.Action) {
				a.ExecInPod(ctx, a.CurlCommandWithOutput(externalEcho))
			})
			i++
		}
	}
}
