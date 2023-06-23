// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/k8s"
)

const (
	LongTimeout  = 5 * time.Minute
	ShortTimeout = 30 * time.Second

	PollInterval = 1 * time.Second
)

// WaitForDeployment waits until the specified deployment becomes ready.
func WaitForDeployment(ctx context.Context, log Logger, client *k8s.Client, namespace string, name string) error {
	log.Logf("⌛ [%s] Waiting for deployment %s/%s to become ready...", client.ClusterName(), namespace, name)

	ctx, cancel := context.WithTimeout(ctx, LongTimeout)
	defer cancel()
	for {
		err := client.CheckDeploymentStatus(ctx, namespace, name)
		if err == nil {
			return nil
		}

		log.Debugf("[%s] Deployment %s/%s is not yet ready: %s", client.ClusterName(), namespace, name, err)

		select {
		case <-time.After(PollInterval):
		case <-ctx.Done():
			return fmt.Errorf("timeout reached waiting for deployment %s/%s to become ready (last error: %w)",
				namespace, name, err)
		}
	}
}

// WaitForCiliumEndpoint waits until the specified cilium endpoint gets created.
func WaitForCiliumEndpoint(ctx context.Context, log Logger, client *k8s.Client, namespace, name string) error {
	log.Logf("⌛ [%s] Waiting for CiliumEndpoint for pod %s/%s to appear...", client.ClusterName(), namespace, name)

	ctx, cancel := context.WithTimeout(ctx, ShortTimeout)
	defer cancel()
	for {
		_, err := client.GetCiliumEndpoint(ctx, namespace, name, metav1.GetOptions{})
		if err == nil {
			return nil
		}

		log.Debugf("[%s] Error retrieving CiliumEndpoint for pod %s/%s: %s", client.ClusterName(), namespace, name, err)

		select {
		case <-time.After(PollInterval):
		case <-ctx.Done():
			return fmt.Errorf("timeout reached waiting for CiliumEndpoint %s/%s to appear (last error: %w)",
				namespace, name, err)
		}
	}
}

// WaitForPodDNS waits until src can query the DNS server on dst successfully.
func WaitForPodDNS(ctx context.Context, log Logger, src, dst Pod) error {
	log.Logf("⌛ [%s] Waiting for pod %s to reach DNS server on %s pod...",
		src.K8sClient.ClusterName(), src.Name(), dst.Name())

	ctx, cancel := context.WithTimeout(ctx, ShortTimeout)
	defer cancel()
	for {
		// We don't care about the actual response content, we just want to check the DNS operativity.
		// Since the coreDNS test server has been deployed with the "local" plugin enabled,
		// we query it with a so-called "local request" (e.g. "localhost") to get a response.
		// See https://coredns.io/plugins/local/ for more info.
		target := "localhost"
		stdout, err := src.K8sClient.ExecInPod(ctx, src.Namespace(), src.NameWithoutNamespace(),
			"", []string{"nslookup", target, dst.Address(IPFamilyAny)})

		if err == nil {
			return nil
		}

		log.Debugf("[%s] Error looking up %s from pod %s to server on pod %s: %s: %s",
			src.K8sClient.ClusterName(), target, src.Name(), dst.Name(), err, stdout.String())

		select {
		case <-time.After(PollInterval):
		case <-ctx.Done():
			return fmt.Errorf("timeout reached waiting for lookup for %s from pod %s to server on pod %s to succeed (last error: %w)",
				target, src.Name(), dst.Name(), err,
			)
		}
	}
}

// WaitForCoreDNS waits until the client pod can reach coredns.
func WaitForCoreDNS(ctx context.Context, log Logger, client Pod) error {
	log.Logf("⌛ [%s] Waiting for pod %s to reach default/kubernetes service...",
		client.K8sClient.ClusterName(), client.Name())

	ctx, cancel := context.WithTimeout(ctx, ShortTimeout)
	defer cancel()
	for {
		target := "kubernetes.default"
		stdout, err := client.K8sClient.ExecInPod(ctx, client.Namespace(), client.NameWithoutNamespace(),
			"", []string{"nslookup", target})
		if err == nil {
			return nil
		}

		log.Debugf("[%s] Error looking up %s from pod %s: %s: %s",
			client.K8sClient.ClusterName(), target, client.Name(), err, stdout.String())

		select {
		case <-time.After(PollInterval):
		case <-ctx.Done():
			return fmt.Errorf("timeout reached waiting for lookup for %s from pod %s to succeed (last error: %w)",
				target, client.Name(), err)
		}
	}
}

// WaitForService waits until the given service is synchronized in CoreDNS.
func WaitForService(ctx context.Context, log Logger, client Pod, service Service) error {
	log.Logf("⌛ [%s] Waiting for Service %s to become ready...", client.K8sClient.ClusterName(), service.Name())

	ctx, cancel := context.WithTimeout(ctx, ShortTimeout)
	defer cancel()

	for {
		stdout, err := client.K8sClient.ExecInPod(ctx,
			client.Namespace(), client.NameWithoutNamespace(), "",
			[]string{"nslookup", service.Service.Name}) // BusyBox nslookup doesn't support any arguments.

		// Lookup successful.
		if err == nil {
			svcIP := service.Service.Spec.ClusterIP
			if svcIP == "" {
				return nil
			}

			nslookupStr := strings.ReplaceAll(stdout.String(), "\r\n", "\n")
			if strings.Contains(nslookupStr, "Address: "+svcIP+"\n") {
				return nil
			}
			err = fmt.Errorf("Service IP %q not found in nslookup output %q", svcIP, nslookupStr)
		}

		log.Debugf("[%s] Error checking service %s: %s: %s",
			client.K8sClient.ClusterName(), service.Name(), err, stdout.String())

		select {
		case <-time.After(PollInterval):
		case <-ctx.Done():
			return fmt.Errorf("timeout reached waiting for service %s (last error: %w)", service.Name(), err)
		}
	}
}

// WaitForNodePorts waits until all the nodeports in a service are available on a given node.
func WaitForNodePorts(ctx context.Context, log Logger, client Pod, nodeIP string, service Service) error {
	ctx, cancel := context.WithTimeout(ctx, ShortTimeout)
	defer cancel()

	for _, port := range service.Service.Spec.Ports {
		nodePort := port.NodePort
		if nodePort == 0 {
			continue
		}

		log.Logf("⌛ [%s] Waiting for NodePort %s:%d (%s) to become ready...",
			client.K8sClient.ClusterName(), nodeIP, nodePort, service.Name())
		for {
			stdout, err := client.K8sClient.ExecInPod(ctx,
				client.Namespace(), client.NameWithoutNamespace(), "",
				[]string{"nc", "-w", "3", "-z", nodeIP, strconv.Itoa(int(nodePort))})
			if err == nil {
				break
			}

			log.Debugf("[%s] Error checking NodePort %s:%d (%s): %s: %s",
				client.K8sClient.ClusterName(), nodeIP, nodePort, service.Name(), err, stdout.String())

			select {
			case <-time.After(PollInterval):
			case <-ctx.Done():
				return fmt.Errorf("timeout reached waiting for NodePort %s:%d (%s) (last error: %w)",
					nodeIP, nodePort, service.Name(), err)
			}
		}
	}

	return nil
}

// WaitForIPCache waits until all the specified pods are present in the IPCache of the given agent.
func WaitForIPCache(ctx context.Context, log Logger, agent Pod, pods []Pod) error {
	log.Logf("⌛ [%s] Waiting for Cilium pod %s to have all the pod IPs in eBPF IPCache...",
		agent.K8sClient.ClusterName(), agent.Name())

	ctx, cancel := context.WithTimeout(ctx, ShortTimeout)
	defer cancel()

	for {
		err := validateIPCache(ctx, agent, pods)
		if err == nil {
			return nil
		}

		log.Debugf("[%s] Error checking pod IPs in IPCache: %s", agent.K8sClient.ClusterName(), err)

		select {
		case <-time.After(PollInterval):
		case <-ctx.Done():
			return fmt.Errorf("timeout reached waiting for pod IPs to be in IPCache of Cilium pod %s (last error: %w)",
				agent.Name(), err)
		}
	}
}

func validateIPCache(ctx context.Context, agent Pod, pods []Pod) error {
	stdout, err := agent.K8sClient.ExecInPod(ctx, agent.Namespace(), agent.NameWithoutNamespace(),
		defaults.AgentContainerName, []string{"cilium", "bpf", "ipcache", "list", "-o", "json"})
	if err != nil {
		return fmt.Errorf("failed to list ipcache bpf map: %w", err)
	}

	var ic ipCache
	if err := json.Unmarshal(stdout.Bytes(), &ic); err != nil {
		return fmt.Errorf("failed to unmarshal Cilium ipcache stdout json: %w", err)
	}

	for _, pod := range pods {
		if _, err := ic.findPodID(pod); err != nil {
			return fmt.Errorf("couldn't find pod %s in ipcache: %w", pod.Name(), err)
		}
	}

	return nil
}
