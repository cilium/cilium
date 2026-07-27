// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node/addressing"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

const (
	notExistMsg          = "does not exist"
	alreadyExistMsg      = "already exists"
	testMulticastGroupIP = "239.255.9.9"
	testSocatPort        = 6666
)

// Having data to restore group and subscriber status after testing
var NodeWithoutGroup []string
var NotSubscribePodAddress map[string][]v2.NodeAddress
var ipToPodMap lock.Map[v2.NodeAddress, string]
var NodeWithoutGroupMu lock.RWMutex
var NotSubscribePodAddressMu lock.RWMutex

type socatMulticast struct {
	check.ScenarioBase
}

func SocatMulticast() check.Scenario {
	return &socatMulticast{
		ScenarioBase: check.NewScenarioBase(),
	}
}

func (s *socatMulticast) Name() string {
	return "multicast"
}

func (s *socatMulticast) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()
	defer func() {
		s.cleanup(ctx, t)
	}()
	NotSubscribePodAddress = make(map[string][]v2.NodeAddress)

	// Add all cilium nodes to the multicast group
	if err := s.addAllNodes(ctx, t); err != nil {
		t.Fatalf("Fatal error occurred while adding all cilium nodes to multicast group: %v", err)
	}

	bgCtx, cancelBg := context.WithCancel(ctx)
	defer cancelBg()

	var wg sync.WaitGroup

	// Sender: Start repeated socat multicast client in the background)
	for _, clientPod := range ct.SocatClientPods() {
		wg.Add(1)
		go func(pod check.Pod) {
			defer wg.Done()
			cmd := ct.SocatClientCommand(testSocatPort, testMulticastGroupIP)
			doneCh := make(chan struct{})
			go func() {
				_, stdErr, err := pod.K8sClient.ExecInPodWithStderr(bgCtx, pod.Pod.Namespace, pod.Pod.Name, pod.Pod.Labels["name"], cmd)
				if err != nil && !strings.Contains(err.Error(), "context canceled") {
					errMsg := fmt.Sprintf("Error: %v, Stderr: %s", err, stdErr.String())
					t.Logf("Error in background task for pod %s: %v", pod.Name(), errMsg)
				}
				close(doneCh)
			}()
			select {
			case <-doneCh:
				// Task finished normally
			case <-bgCtx.Done():
				// Context was cancelled, handle cleanup
				cancelCmd := ct.KillMulticastTestSender()
				_, _, err := pod.K8sClient.ExecInPodWithStderr(ctx, pod.Pod.Namespace, pod.Pod.Name, pod.Pod.Labels["name"], cancelCmd)
				if err != nil {
					t.Logf("Error cancelling command for pod %s: %v", pod.Name(), err)
				}
			}
		}(clientPod)
	}

	// Receiver: Execute socat multicast server and check if multicast packets are coming in.
	for _, socatServerPod := range ct.SocatServerPods() {
		t.NewAction(s, "socat multicast", &socatServerPod, nil, features.IPFamilyV4).Run(func(a *check.Action) {
			cmd := ct.SocatServer1secCommand(socatServerPod, testSocatPort, testMulticastGroupIP)
			// The exit code of socat server command with timeout is 0 if a packet is received,
			// and 124 if no packet is received.
			a.ExecInPod(ctx, cmd)
		})
	}

	cancelBg()
	wg.Wait()
}

// Restore the state of the multicast group and subscriber after the test
func (s *socatMulticast) cleanup(ctx context.Context, t *check.Test) {
	ct := t.Context()
	client := ct.K8sClient()
	ciliumNodesList, err := client.ListCiliumNodes(ctx)
	if err != nil {
		t.Fatalf("Fatal error occurred while listing cilium nodes: %v", err)
	}
	ciliumNodes := ciliumNodesList.Items
	for _, ciliumNode := range ciliumNodes {
		if s.isNodeWithoutGroup(ciliumNode.Name) {
			if err := s.delGroup(ctx, t, ciliumNode.Name); err != nil {
				t.Fatalf("Fatal error occurred while deleting multicast group: %v", err)
			}
		} else {
			for _, podAddress := range NotSubscribePodAddress[ciliumNode.Name] {
				if s.isNotSubscribePodAddress(ciliumNode.Name, podAddress) {
					if err := s.delSubscriber(ctx, t, ciliumNode.Name, podAddress.IP); err != nil {
						t.Fatalf("Fatal error occurred while deleting subscriber: %v", err)
					}
				}
			}
		}
	}
}

func (s *socatMulticast) addNodeWithoutGroup(nodeName string) {
	NodeWithoutGroupMu.Lock()
	defer NodeWithoutGroupMu.Unlock()
	NodeWithoutGroup = append(NodeWithoutGroup, nodeName)
}

func (s *socatMulticast) isNodeWithoutGroup(nodeName string) bool {
	NodeWithoutGroupMu.RLock()
	defer NodeWithoutGroupMu.RUnlock()
	return slices.Contains(NodeWithoutGroup, nodeName)
}

func (s *socatMulticast) addNotSubscribePodAddress(nodeName string, podAddress v2.NodeAddress) {
	NotSubscribePodAddressMu.Lock()
	defer NotSubscribePodAddressMu.Unlock()
	NotSubscribePodAddress[nodeName] = append(NotSubscribePodAddress[nodeName], podAddress)
}

func (s *socatMulticast) isNotSubscribePodAddress(nodeName string, podAddress v2.NodeAddress) bool {
	NotSubscribePodAddressMu.RLock()
	defer NotSubscribePodAddressMu.RUnlock()
	for _, address := range NotSubscribePodAddress[nodeName] {
		if address.IP == podAddress.IP {
			return true
		}
	}
	return false
}

func (s *socatMulticast) getCiliumNode(ctx context.Context, t *check.Test, nodeName string) (v2.CiliumNode, error) {
	ct := t.Context()
	client := ct.K8sClient()
	ciliumNodes, err := client.ListCiliumNodes(ctx)
	if err != nil {
		return v2.CiliumNode{}, err
	}
	var ciliumNode v2.CiliumNode
	for _, node := range ciliumNodes.Items {
		if node.Name == nodeName {
			ciliumNode = node
		}
	}
	return ciliumNode, nil
}

func (s *socatMulticast) getCiliumInternalIP(ctx context.Context, t *check.Test, nodeName string) (v2.NodeAddress, error) {
	ciliumNode, err := s.getCiliumNode(ctx, t, nodeName)
	if err != nil {
		return v2.NodeAddress{}, fmt.Errorf("unable to get cilium node: %w", err)
	}
	addrs := ciliumNode.Spec.Addresses
	var ciliumInternalIP v2.NodeAddress
	for _, addr := range addrs {
		if addr.AddrType() == addressing.NodeCiliumInternalIP {
			ip, err := netip.ParseAddr(addr.IP)
			if err != nil {
				continue
			}
			if ip.Is4() {
				ciliumInternalIP = addr
			}
		}
	}
	if ciliumInternalIP.IP == "" {
		return v2.NodeAddress{}, fmt.Errorf("ciliumInternalIP not found")
	}
	return ciliumInternalIP, nil
}

// To record the correspondence between CiliumInternalIp and cilium-agent
func (s *socatMulticast) populateMaps(ctx context.Context, t *check.Test, ciliumPods []corev1.Pod) error {
	var wg sync.WaitGroup
	errCh := make(chan error, len(ciliumPods))
	wg.Add(len(ciliumPods))

	for _, ciliumPod := range ciliumPods {
		go func(pod corev1.Pod) {
			defer wg.Done()
			ciliumInternalIP, err := s.getCiliumInternalIP(ctx, t, pod.Spec.NodeName)
			if err != nil {
				errCh <- err
				return
			}
			ipToPodMap.Store(ciliumInternalIP, pod.Name)
		}(ciliumPod)
	}

	wg.Wait()
	close(errCh)

	var errRet error
	for fetchData := range errCh {
		errRet = errors.Join(errRet, fetchData)
	}
	return errRet
}

// create multicast group and add all cilium nodes to the multicast group for testing
func (s *socatMulticast) addAllNodes(ctx context.Context, t *check.Test) error {
	ct := t.Context()
	client := ct.K8sClient()

	ciliumPodsList, err := client.ListPods(ctx, ct.Params().CiliumNamespace, metav1.ListOptions{LabelSelector: defaults.AgentPodSelector})
	if err != nil {
		return err
	}
	ciliumPods := ciliumPodsList.Items

	// Create a map of ciliumInternalIPs of all nodes
	if err := s.populateMaps(ctx, t, ciliumPods); err != nil {
		return err
	}

	var wg sync.WaitGroup
	errCh := make(chan error, len(ciliumPods))
	wg.Add(len(ciliumPods))

	for _, ciliumPod := range ciliumPods {
		go func(pod corev1.Pod) {
			defer wg.Done()
			// If there are not specified multicast group, create it
			cmd := []string{"cilium-dbg", "bpf", "multicast", "subscriber", "list", testMulticastGroupIP}
			_, stdErr, err := client.ExecInPodWithStderr(ctx, pod.Namespace, pod.Name, defaults.AgentContainerName, cmd)
			if err != nil {
				if !strings.Contains(stdErr.String(), notExistMsg) {
					errMsg := fmt.Sprintf("Error: %v, Stderr: %s", err, stdErr.String())
					errCh <- errors.New(errMsg)
					t.Fatalf("Fatal error occurred while checking multicast group %s in %s", testMulticastGroupIP, pod.Spec.NodeName)
					return
				}
				s.addNodeWithoutGroup(pod.Spec.NodeName)
				cmd = []string{"cilium-dbg", "bpf", "multicast", "group", "add", testMulticastGroupIP}
				_, stdErr, err := client.ExecInPodWithStderr(ctx, pod.Namespace, pod.Name, defaults.AgentContainerName, cmd)
				if err != nil {
					errMsg := fmt.Sprintf("Error: %v, Stderr: %s", err, stdErr.String())
					errCh <- errors.New(errMsg)
					t.Fatalf("Fatal error occurred while creating multicast group %s in %s", testMulticastGroupIP, pod.Spec.NodeName)
					return
				}
			}
			// Add all ciliumInternalIPs of all nodes to the multicast group as subscribers
			ipToPodMap.Range(func(ip v2.NodeAddress, podName string) bool {
				if ip.IP != "" && pod.Name != podName { // My node itself does not need to be in a multicast group.
					cmd = []string{"cilium-dbg", "bpf", "multicast", "subscriber", "add", testMulticastGroupIP, ip.IP}
					_, stdErr, err := client.ExecInPodWithStderr(ctx, pod.Namespace, pod.Name, defaults.AgentContainerName, cmd)
					if err == nil {
						s.addNotSubscribePodAddress(pod.Spec.NodeName, ip)
					} else if !strings.Contains(stdErr.String(), alreadyExistMsg) {
						errMsg := fmt.Sprintf("Error: %v, Stderr: %s", err, stdErr.String())
						errCh <- errors.New(errMsg)
						t.Fatalf("Fatal error occurred while adding node %s to multicast group %s in %s", ip.IP, testMulticastGroupIP, pod.Spec.NodeName)
						return false // Stop iteration
					}
				}
				return true // Continue iteration
			})
		}(ciliumPod)
	}

	wg.Wait()
	close(errCh)

	var errRet error
	for fetchData := range errCh {
		errRet = errors.Join(errRet, fetchData)
	}
	return errRet
}

// Delete multicast group in designated node
func (s *socatMulticast) delGroup(ctx context.Context, t *check.Test, nodeName string) error {
	ct := t.Context()
	client := ct.K8sClient()

	ciliumPodsList, err := client.ListPods(ctx, ct.Params().CiliumNamespace, metav1.ListOptions{LabelSelector: defaults.AgentPodSelector})
	if err != nil {
		return err
	}
	ciliumPods := ciliumPodsList.Items

	for _, ciliumPod := range ciliumPods {
		if nodeName == ciliumPod.Spec.NodeName {
			cmd := []string{"cilium-dbg", "bpf", "multicast", "group", "delete", testMulticastGroupIP}
			_, stdErr, err := client.ExecInPodWithStderr(ctx, ciliumPod.Namespace, ciliumPod.Name, defaults.AgentContainerName, cmd)
			if err != nil {
				if !strings.Contains(stdErr.String(), notExistMsg) {
					errMsg := fmt.Sprintf("Error: %v while deleting Multicast Group for test %s, Stderr: %s", err, testMulticastGroupIP, stdErr.String())
					return errors.New(errMsg)
				}
			}
			break
		}
	}
	return nil
}

// Delete designated subscriber in designated node
func (s *socatMulticast) delSubscriber(ctx context.Context, t *check.Test, nodeName string, subscriberIP string) error {
	ct := t.Context()
	client := ct.K8sClient()

	ciliumPodsList, err := client.ListPods(ctx, ct.Params().CiliumNamespace, metav1.ListOptions{LabelSelector: defaults.AgentPodSelector})
	if err != nil {
		return err
	}
	ciliumPods := ciliumPodsList.Items

	for _, ciliumPod := range ciliumPods {
		if nodeName == ciliumPod.Spec.NodeName {
			cmd := []string{"cilium-dbg", "bpf", "multicast", "subscriber", "delete", testMulticastGroupIP, subscriberIP}
			_, stdErr, err := client.ExecInPodWithStderr(ctx, ciliumPod.Namespace, ciliumPod.Name, defaults.AgentContainerName, cmd)
			if err != nil {
				if !strings.Contains(stdErr.String(), notExistMsg) {
					errMsg := fmt.Sprintf("Error: %v while removing %s from Multicast Group %s Stderr: %s", err, subscriberIP, testMulticastGroupIP, stdErr.String())
					return errors.New(errMsg)
				}
			}
			break
		}
	}
	return nil
}
