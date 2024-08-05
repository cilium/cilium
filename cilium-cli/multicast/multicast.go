// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multicast

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/cilium-cli/k8s"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/node/addressing"
)

// IMPORTANT: The names of the keys in the JSON and the contents of the error messages must be the same as those
// defined in cilium-dbg/cmd/bpf_multicast_group.go and cilium-dbg/cmd/bpf_multicast_subscriber.go
// in cilium/cilium repository.

const (
	padding         = 3
	minWidth        = 5
	paddingChar     = ' '
	alreadyExistMsg = "already exists"
	notExistMsg     = "does not exist"
)

var (
	errMissingGroup = errors.New(notExistMsg)
)

type Multicast struct {
	client *k8s.Client
	params Parameters
}

type Parameters struct {
	CiliumNamespace  string
	Writer           io.Writer
	WaitDuration     time.Duration
	MulticastGroupIP string
	All              bool
	Output           string
}

type Subscriber struct {
	SAddr    string `json:"SAddr"`
	Ifindex  int    `json:"Ifindex"`
	IsRemote bool   `json:"IsRemote"`
}

type GroupSubscriberData struct {
	GroupAddress string       `json:"group_address"`
	Subscribers  []Subscriber `json:"subscribers"`
}

type NodeSubscriberData struct {
	Node   string                `json:"node"`
	Groups []GroupSubscriberData `json:"groups"`
}

type NodeGroupData struct {
	Node   string   `json:"node"`
	Groups []string `json:"groups"`
}

func NewMulticast(client *k8s.Client, p Parameters) *Multicast {
	return &Multicast{
		client: client,
		params: p,
	}
}

func (m *Multicast) getCiliumNode(ctx context.Context, nodeName string) (v2.CiliumNode, error) {
	ciliumNodes, err := m.client.ListCiliumNodes(ctx)
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

func (m *Multicast) getCiliumInternalIP(nodeName string) (v2.NodeAddress, error) {
	ctx, cancel := context.WithTimeout(context.Background(), m.params.WaitDuration)
	defer cancel()
	ciliumNode, err := m.getCiliumNode(ctx, nodeName)
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

// Get the list of multicast groups in the specified cilium-agent
func (m *Multicast) getGroupList(ctx context.Context, pod corev1.Pod) ([]string, error) {
	cmd := []string{"cilium-dbg", "bpf", "multicast", "group", "list", "-o", "json"}
	outputByte, stdErr, err := m.client.ExecInPodWithStderr(ctx, pod.Namespace, pod.Name, defaults.AgentContainerName, cmd)
	if err != nil {
		errMsg := fmt.Sprintf("Error: %v, Stderr: %s", err, stdErr.String())
		return nil, errors.New(errMsg)
	}
	var groups []string
	if err := json.Unmarshal(outputByte.Bytes(), &groups); err != nil {
		return nil, err
	}
	return groups, nil
}

func (m *Multicast) groupTablePrint(allGroups []NodeGroupData) {
	w := tabwriter.NewWriter(m.params.Writer, minWidth, 0, padding, paddingChar, 0)
	fmt.Fprintf(w, "Node\tGroup\t\n")
	for _, nodeGroup := range allGroups {
		if len(nodeGroup.Groups) == 0 {
			// If the node has no groups, print the node name only
			fmt.Fprintf(w, "%s\t\t\n", nodeGroup.Node)
		} else {
			nodePrinted := false
			for _, group := range nodeGroup.Groups {
				if !nodePrinted {
					fmt.Fprintf(w, "%s\t%s\t\n", nodeGroup.Node, group)
					nodePrinted = true
				} else {
					fmt.Fprintf(w, "\t%s\t\n", group)
				}
			}
		}
	}
	w.Flush()
}

// ListGroup lists multicast groups in every node
func (m *Multicast) ListGroups() error {
	ctx, cancel := context.WithTimeout(context.Background(), m.params.WaitDuration)
	defer cancel()

	ciliumPodsList, err := m.client.ListPods(ctx, m.params.CiliumNamespace, metav1.ListOptions{LabelSelector: defaults.AgentPodSelector})
	if err != nil {
		return err
	}
	ciliumPods := ciliumPodsList.Items

	var wg sync.WaitGroup
	wg.Add(len(ciliumPods))

	type listData struct {
		nodeGroup NodeGroupData
		err       error
	}

	listDataCh := make(chan listData, len(ciliumPods))

	for _, ciliumPod := range ciliumPods {
		go func(pod corev1.Pod) {
			defer wg.Done()
			// List multicast groups
			groupList, err := m.getGroupList(ctx, pod)
			if err != nil {
				listDataCh <- listData{
					nodeGroup: NodeGroupData{Node: pod.Spec.NodeName, Groups: nil},
					err:       err,
				}
				return
			}
			listDataCh <- listData{
				nodeGroup: NodeGroupData{Node: pod.Spec.NodeName, Groups: groupList},
				err:       nil,
			}

		}(ciliumPod)
	}

	wg.Wait()
	close(listDataCh)

	var allGroups []NodeGroupData
	var errRet error
	for listData := range listDataCh {
		if listData.err == nil {
			allGroups = append(allGroups, listData.nodeGroup)
		} else {
			errRet = errors.Join(errRet, listData.err)
		}
	}

	if errRet != nil {
		return errRet
	}

	// Print the output in the requested format.
	if m.params.Output == "json" {
		jsonOutput, err := json.MarshalIndent(allGroups, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(m.params.Writer, string(jsonOutput))
		return nil
	}
	m.groupTablePrint(allGroups)

	return nil
}

// Get the list of multicast group and subscribers in the specified cilium-agent
func (m *Multicast) getGroupForSubscriberList(ctx context.Context, pod corev1.Pod, target string) ([]GroupSubscriberData, error) {
	cmd := []string{"cilium-dbg", "bpf", "multicast", "subscriber", "list", target, "-o", "json"}
	outputByte, stdErr, err := m.client.ExecInPodWithStderr(ctx, pod.Namespace, pod.Name, defaults.AgentContainerName, cmd)
	if err != nil {
		if strings.Contains(stdErr.String(), notExistMsg) {
			fmt.Fprintf(m.params.Writer, "Multicast group %s does not exist in %s\n", target, pod.Spec.NodeName)
			return nil, errMissingGroup
		}
		errMsg := fmt.Sprintf("Error: %v, Stderr: %s", err, stdErr.String())
		return nil, errors.New(errMsg)
	}
	var groups []GroupSubscriberData
	err = json.Unmarshal(outputByte.Bytes(), &groups)
	if err != nil {
		return nil, err
	}

	return groups, nil
}

func (m *Multicast) printSubscriberTable(allGroups []NodeSubscriberData) {
	w := tabwriter.NewWriter(m.params.Writer, minWidth, 0, padding, paddingChar, 0)

	fmt.Fprintln(w, "Node\tGroup\tSubscriber\tType")

	for _, node := range allGroups {
		nodePrinted := false

		if len(node.Groups) == 0 {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", node.Node, "", "", "")
			continue
		}

		for _, group := range node.Groups {
			groupPrinted := false

			if len(group.Subscribers) == 0 {
				if !nodePrinted {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", node.Node, group.GroupAddress, "", "")
					nodePrinted = true
				} else {
					fmt.Fprintf(w, "\t%s\t%s\t%s\n", group.GroupAddress, "", "")
				}
				continue
			}

			for _, subscriber := range group.Subscribers {
				endpointType := "Local Endpoint"
				if subscriber.IsRemote {
					endpointType = "Remote Node"
				}

				if !nodePrinted {
					if !groupPrinted {
						fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", node.Node, group.GroupAddress, subscriber.SAddr, endpointType)
						groupPrinted = true
					} else {
						fmt.Fprintf(w, "%s\t\t%s\t%s\n", node.Node, subscriber.SAddr, endpointType)
					}
					nodePrinted = true
				} else {
					if !groupPrinted {
						fmt.Fprintf(w, "\t%s\t%s\t%s\n", group.GroupAddress, subscriber.SAddr, endpointType)
						groupPrinted = true
					} else {
						fmt.Fprintf(w, "\t\t%s\t%s\n", subscriber.SAddr, endpointType)
					}
				}
			}
		}
		// Print node name only if it has no groups or all groups have no subscribers
		if !nodePrinted {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", node.Node, "", "", "")
		}
	}
	w.Flush()
}

// ListSubscriber lists multicast subscribers in every node for the specified multicast group or all multicast groups
func (m *Multicast) ListSubscribers() error {
	if m.params.MulticastGroupIP == "" && !m.params.All {
		return fmt.Errorf("group-ip or all flag must be specified")
	} else if m.params.MulticastGroupIP != "" && m.params.All {
		return fmt.Errorf("only one of group-ip or all flag must be specified")
	}

	var target string
	if m.params.All {
		target = "all"
	} else {
		target = m.params.MulticastGroupIP
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.params.WaitDuration)
	defer cancel()

	ciliumPodsList, err := m.client.ListPods(ctx, m.params.CiliumNamespace, metav1.ListOptions{LabelSelector: defaults.AgentPodSelector})
	if err != nil {
		return err
	}
	ciliumPods := ciliumPodsList.Items

	var wg sync.WaitGroup
	wg.Add(len(ciliumPods))

	type listData struct {
		nodeSubscriber NodeSubscriberData
		err            error
	}
	listDataCh := make(chan listData, len(ciliumPods))

	// Iterate over each Cilium pod.
	for _, ciliumPod := range ciliumPods {
		go func(pod corev1.Pod) {
			defer wg.Done()

			// List multicast subscribers.
			groups, err := m.getGroupForSubscriberList(ctx, pod, target)
			if err != nil {
				if errors.Is(err, errMissingGroup) {
					listDataCh <- listData{
						nodeSubscriber: NodeSubscriberData{Node: pod.Spec.NodeName, Groups: nil},
						err:            nil,
					}
					return
				}
				listDataCh <- listData{
					nodeSubscriber: NodeSubscriberData{Node: pod.Spec.NodeName, Groups: nil},
					err:            err,
				}
				return
			}
			listDataCh <- listData{
				nodeSubscriber: NodeSubscriberData{Node: pod.Spec.NodeName, Groups: groups},
				err:            nil,
			}
		}(ciliumPod)
	}

	// Wait for all goroutines to finish and close the error channel.
	wg.Wait()
	close(listDataCh)

	var allGroups []NodeSubscriberData
	var errRet error

	for listData := range listDataCh {
		if listData.err == nil {
			allGroups = append(allGroups, listData.nodeSubscriber)
		} else {
			errRet = errors.Join(errRet, listData.err)
		}
	}

	if errRet != nil {
		return errRet
	}

	// Print the output in the requested format.
	if m.params.Output == "json" {
		jsonOutput, err := json.MarshalIndent(allGroups, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(m.params.Writer, string(jsonOutput))
		return nil
	}
	m.printSubscriberTable(allGroups)

	return nil
}

func (m *Multicast) populateMaps(ciliumPods []corev1.Pod, ipToPodMap map[v2.NodeAddress]string, ipToNodeMap map[v2.NodeAddress]string) error {
	var wg sync.WaitGroup
	errCh := make(chan error, len(ciliumPods))
	wg.Add(len(ciliumPods))

	for _, ciliumPod := range ciliumPods {
		go func(pod corev1.Pod) {
			defer wg.Done()
			ciliumInternalIP, err := m.getCiliumInternalIP(pod.Spec.NodeName)
			if err != nil {
				errCh <- err
				return
			}
			ipToPodMap[ciliumInternalIP] = pod.Name
			ipToNodeMap[ciliumInternalIP] = pod.Spec.NodeName
		}(ciliumPod)
	}

	wg.Wait()
	close(errCh)

	var errRet error
	for fetchdata := range errCh {
		if fetchdata != nil {
			errRet = errors.Join(errRet, fetchdata)
		}
	}
	return errRet
}

// AddAllNodes add CiliumInternalIPs of all nodes to the specified multicast group as subscribers in every cilium-agent
func (m *Multicast) AddAllNodes() error {
	if m.params.MulticastGroupIP == "" {
		return fmt.Errorf("group-ip must be specified")
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.params.WaitDuration)
	defer cancel()

	ciliumPodsList, err := m.client.ListPods(ctx, m.params.CiliumNamespace, metav1.ListOptions{LabelSelector: defaults.AgentPodSelector})
	if err != nil {
		return err
	}
	ciliumPods := ciliumPodsList.Items

	// Create a map of ciliumInternalIPs of all nodes
	ipToPodMap := make(map[v2.NodeAddress]string)
	ipToNodeMap := make(map[v2.NodeAddress]string)
	if err := m.populateMaps(ciliumPods, ipToPodMap, ipToNodeMap); err != nil {
		return err
	}

	var wg sync.WaitGroup
	errCh := make(chan error, len(ciliumPods))
	wg.Add(len(ciliumPods))

	for _, ciliumPod := range ciliumPods {
		go func(pod corev1.Pod) {
			defer wg.Done()
			// If there are not specified multicast group, create it
			cmd := []string{"cilium-dbg", "bpf", "multicast", "subscriber", "list", m.params.MulticastGroupIP}
			_, stdErr, err := m.client.ExecInPodWithStderr(ctx, pod.Namespace, pod.Name, defaults.AgentContainerName, cmd)
			if err != nil {
				if !strings.Contains(stdErr.String(), notExistMsg) {
					errMsg := fmt.Sprintf("Error: %v, Stderr: %s", err, stdErr.String())
					errCh <- errors.New(errMsg)
					fmt.Fprintf(m.params.Writer, "Fatal error occurred while checking multicast group %s in %s\n", m.params.MulticastGroupIP, pod.Spec.NodeName)
					return
				}
				cmd = []string{"cilium-dbg", "bpf", "multicast", "group", "add", m.params.MulticastGroupIP}
				_, stdErr, err := m.client.ExecInPodWithStderr(ctx, pod.Namespace, pod.Name, defaults.AgentContainerName, cmd)
				if err != nil {
					errMsg := fmt.Sprintf("Error: %v, Stderr: %s", err, stdErr.String())
					errCh <- errors.New(errMsg)
					fmt.Fprintf(m.params.Writer, "Unable to create multicast group %s in %s by fatal error\n", m.params.MulticastGroupIP, pod.Spec.NodeName)
					return
				}
			}

			// Add all ciliumInternalIPs of all nodes to the multicast group as subscribers
			cnt := 0
			var nodeLists []string
			var displayOutput string
			for ip, podName := range ipToPodMap {
				if ip.IP != "" && pod.Name != podName { // My node itself does not need to be in a multicast group.
					cmd = []string{"cilium-dbg", "bpf", "multicast", "subscriber", "add", m.params.MulticastGroupIP, ip.IP}
					_, stdErr, err := m.client.ExecInPodWithStderr(ctx, pod.Namespace, pod.Name, defaults.AgentContainerName, cmd)
					if err == nil {
						cnt++
						nodeLists = append(nodeLists, ipToNodeMap[ip])
					} else if !strings.Contains(stdErr.String(), alreadyExistMsg) {
						errMsg := fmt.Sprintf("Error: %v, Stderr: %s", err, stdErr.String())
						errCh <- errors.New(errMsg)
						fmt.Fprintf(m.params.Writer, "Unable to add node %s to multicast group %s in %s by fatal error\n", ip.IP, m.params.MulticastGroupIP, pod.Spec.NodeName)
						return
					}
				}
			}
			if cnt == 0 {
				fmt.Fprintf(m.params.Writer, "Unable to add any node to multicast group %s in %s\n", m.params.MulticastGroupIP, pod.Spec.NodeName)
				return
			}
			if cnt == 1 {
				displayOutput = "Added a node ("
			} else {
				displayOutput = fmt.Sprintf("Added %d nodes (", cnt)
			}
			for i, node := range nodeLists {
				if i == len(nodeLists)-1 {
					displayOutput += node
				} else {
					displayOutput += node + ", "
				}
			}
			displayOutput += fmt.Sprintf(") to multicast group %s in %s\n", m.params.MulticastGroupIP, pod.Spec.NodeName)
			fmt.Fprint(m.params.Writer, displayOutput)
		}(ciliumPod)
	}

	wg.Wait()
	close(errCh)

	var errRet error
	for fetchdata := range errCh {
		if fetchdata != nil {
			errRet = errors.Join(errRet, fetchdata)
		}
	}
	return errRet
}

// DelAllNodes delete CiliumInternalIPs of all nodes from the specified multicast group's subscribers in every cilium-agent
func (m *Multicast) DelAllNodes() error {
	if m.params.MulticastGroupIP == "" {
		return fmt.Errorf("group-ip must be specified")
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.params.WaitDuration)
	defer cancel()

	ciliumPodsList, err := m.client.ListPods(ctx, m.params.CiliumNamespace, metav1.ListOptions{LabelSelector: defaults.AgentPodSelector})
	if err != nil {
		return err
	}
	ciliumPods := ciliumPodsList.Items

	var wg sync.WaitGroup
	errCh := make(chan error, len(ciliumPods))
	wg.Add(len(ciliumPods))

	for _, ciliumPod := range ciliumPods {
		go func(pod corev1.Pod) {
			defer wg.Done()
			// Delete all ciliumInternalIPs of all nodes from the multicast group's subscribers
			cmd := []string{"cilium-dbg", "bpf", "multicast", "group", "delete", m.params.MulticastGroupIP}
			_, stdErr, err := m.client.ExecInPodWithStderr(ctx, pod.Namespace, pod.Name, defaults.AgentContainerName, cmd)
			if err != nil {
				if !strings.Contains(stdErr.String(), notExistMsg) {
					errMsg := fmt.Sprintf("Error: %v, Stderr: %s", err, stdErr.String())
					errCh <- errors.New(errMsg)
					fmt.Fprintf(m.params.Writer, "Unable to delete multicast group %s in %s by fatal error\n", m.params.MulticastGroupIP, pod.Spec.NodeName)
					return
				}
				fmt.Fprintf(m.params.Writer, "Multicast group %s does not exist in %s\n", m.params.MulticastGroupIP, pod.Spec.NodeName)
				return
			}
			fmt.Fprintf(m.params.Writer, "Deleted multicast group %s in %s\n", m.params.MulticastGroupIP, pod.Spec.NodeName)
		}(ciliumPod)
	}

	wg.Wait()
	close(errCh)

	var errRet error
	for fetchdata := range errCh {
		if fetchdata != nil {
			errRet = errors.Join(errRet, fetchdata)
		}
	}
	return errRet
}
