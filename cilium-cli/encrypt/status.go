// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package encrypt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	corev1 "k8s.io/api/core/v1"
	"sort"
	"strconv"
	"strings"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/status"
)

type clusterStatus struct {
	TotalNodeCount          int            `json:"total-node-count,omitempty"`
	EncDisabledNodeCount    int            `json:"enc-disabled-node-count,omitempty"`
	EncIPsecNodeCount       int            `json:"enc-ipsec-node-count,omitempty"`
	EncWireguardNodeCount   int            `json:"enc-wireguard-node-count,omitempty"`
	IPsecKeysInUseNodeCount map[int]int    `json:"ipsec-keys-in-use-node-count,omitempty"`
	IPsecMaxSeqNum          string         `json:"ipsec-max-seq-num,omitempty"`
	IPsecErrCount           int            `json:"ipsec-err-count,omitempty"`
	XfrmErrors              map[string]int `json:"xfrm-errors,omitempty"`
	XfrmErrorNodeCount      map[string]int `json:"xfrm-error-node-count,omitempty"`
}

type nodeStatus struct {
	NodeName         string         `json:"node-name,omitempty"`
	EncryptionType   string         `json:"encryption-type,omitempty"`
	IPsecDecryptInts string         `json:"ipsec-decrypt-interfaces-type,omitempty"`
	IPsecMaxSeqNum   string         `json:"ipsec-max-seq-number,omitempty"`
	IPsecKeysInUse   int            `json:"ipsec-keys-in-use,omitempty"`
	IPsecErrCount    int            `json:"ipsec-errors-count,omitempty"`
	XfrmErrors       map[string]int `json:"xfrm-errors,omitempty"`
}

// GetEncryptStatus gets encryption status from all/specific cilium agent pods.
func (s *Status) GetEncryptStatus(ctx context.Context) error {
	ctx, cancelFn := context.WithTimeout(ctx, s.params.WaitDuration)
	defer cancelFn()

	pods, err := s.fetchCiliumPods(ctx)
	if err != nil {
		return err
	}

	res, err := s.fetchEncryptStatusConcurrently(ctx, pods)
	if err != nil {
		return err
	}

	return s.writeStatus(res)
}

func (s *Status) fetchEncryptStatusConcurrently(ctx context.Context, pods []corev1.Pod) (map[string]nodeStatus, error) {
	// res contains data returned from cilium pod
	type res struct {
		nodeName string
		status   nodeStatus
		err      error
	}
	resCh := make(chan res)
	defer close(resCh)

	// concurrently fetch state from each cilium pod
	for _, pod := range pods {
		go func(ctx context.Context, pod corev1.Pod) {
			st, err := s.fetchEncryptStatusFromPod(ctx, pod)
			resCh <- res{
				nodeName: pod.Spec.NodeName,
				status:   st,
				err:      err,
			}
		}(ctx, pod)
	}

	// read from the channel, on error store error and continue to next node.
	var err error
	data := make(map[string]nodeStatus)
	for range pods {
		r := <-resCh
		if r.err != nil {
			err = errors.Join(err, r.err)
			continue
		}
		data[r.nodeName] = r.status
	}
	return data, err
}

func (s *Status) fetchEncryptStatusFromPod(ctx context.Context, pod corev1.Pod) (nodeStatus, error) {
	cmd := []string{"cilium", "encrypt", "status"}
	output, err := s.client.ExecInPod(ctx, pod.Namespace, pod.Name, defaults.AgentContainerName, cmd)
	if err != nil {
		return nodeStatus{}, fmt.Errorf("failed to fetch encryption status from %s: %v", pod.Name, err)
	}
	res, err := nodeStatusFromString(pod.Spec.NodeName, output.String())
	if err != nil {
		return nodeStatus{}, fmt.Errorf("failed to parse encryption status from %s: %v", pod.Name, err)
	}
	return res, nil
}

func nodeStatusFromString(node string, str string) (nodeStatus, error) {
	res := nodeStatus{
		NodeName:   node,
		XfrmErrors: make(map[string]int),
	}
	lines := strings.Split(str, "\n")
	for _, line := range lines {
		parts := strings.Split(line, ":")
		if len(parts) < 2 {
			continue
		}
		key, value := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		switch key {
		case "Encryption":
			res.EncryptionType = value
		case "Max Seq. Number":
			res.IPsecMaxSeqNum = value
		case "Decryption interface(s)":
			res.IPsecDecryptInts = value
		case "Keys in use":
			keys, err := strconv.Atoi(value)
			if err != nil {
				return nodeStatus{}, fmt.Errorf("invalid number 'Keys in use' [%s]: %v", value, err)
			}
			res.IPsecKeysInUse = keys
		case "Errors":
			count, err := strconv.Atoi(value)
			if err != nil {
				return nodeStatus{}, fmt.Errorf("invalid number 'Errors' [%s]: %v", value, err)
			}
			res.IPsecErrCount = count
		default:
			count, err := strconv.Atoi(value)
			if err != nil {
				return nodeStatus{}, fmt.Errorf("invalid number '%s' [%s]: %v", key, value, err)
			}
			res.XfrmErrors[key] = count
		}
	}
	return res, nil
}

func (s *Status) writeStatus(res map[string]nodeStatus) error {
	if s.params.PerNodeDetails {
		for _, n := range res {
			if err := n.printStatus(s.params.Output); err != nil {
				return err
			}
		}
		return nil
	}
	cs, err := clusterNodeStatus(res)
	if err != nil {
		return err
	}
	return cs.printStatus(s.params.Output)
}

func clusterNodeStatus(res map[string]nodeStatus) (clusterStatus, error) {
	cs := clusterStatus{
		TotalNodeCount:          len(res),
		IPsecKeysInUseNodeCount: make(map[int]int),
		XfrmErrors:              make(map[string]int),
		XfrmErrorNodeCount:      make(map[string]int),
	}
	for _, v := range res {
		if v.EncryptionType == "Disabled" {
			cs.EncDisabledNodeCount++
			continue
		}
		if v.EncryptionType == "Wireguard" {
			cs.EncWireguardNodeCount++
			continue
		}
		if v.EncryptionType == "IPsec" {
			cs.EncIPsecNodeCount++
		}
		cs.IPsecKeysInUseNodeCount[v.IPsecKeysInUse]++
		maxSeqNum, err := maxSequenceNumber(v.IPsecMaxSeqNum, cs.IPsecMaxSeqNum)
		if err != nil {
			return clusterStatus{}, err
		}
		cs.IPsecMaxSeqNum = maxSeqNum
		cs.IPsecErrCount += v.IPsecErrCount
		for k, e := range v.XfrmErrors {
			cs.XfrmErrors[k] += e
			cs.XfrmErrorNodeCount[k]++
		}
	}
	return cs, nil
}

func (c clusterStatus) printStatus(format string) error {
	if format == status.OutputJSON {
		return printJSONStatus(c)
	}

	builder := strings.Builder{}
	if c.EncDisabledNodeCount > 0 {
		builder.WriteString(fmt.Sprintf("Encryption: Disabled (%d/%d nodes)\n", c.EncDisabledNodeCount, c.TotalNodeCount))
	}
	if c.EncIPsecNodeCount > 0 {
		builder.WriteString(fmt.Sprintf("Encryption: IPsec (%d/%d nodes)\n", c.EncIPsecNodeCount, c.TotalNodeCount))
		if len(c.IPsecKeysInUseNodeCount) > 0 {
			keys := make([]int, 0, len(c.IPsecKeysInUseNodeCount))
			for k := range c.IPsecKeysInUseNodeCount {
				keys = append(keys, k)
			}
			sort.Ints(keys)
			keyStrs := make([]string, 0, len(keys))
			for _, k := range keys {
				keyStrs = append(keyStrs, fmt.Sprintf("%d on %d/%d", k, c.IPsecKeysInUseNodeCount[k], c.TotalNodeCount))
			}
			builder.WriteString(fmt.Sprintf("IPsec keys in use: %s\n", strings.Join(keyStrs, ", ")))
		}
		builder.WriteString(fmt.Sprintf("IPsec highest Seq. Number: %s across all nodes\n", c.IPsecMaxSeqNum))
		builder.WriteString(fmt.Sprintf("IPsec errors: %d across all nodes\n", c.IPsecErrCount))
		for k, v := range c.XfrmErrors {
			builder.WriteString(fmt.Sprintf("\t%s: %d on %d/%d nodes\n", k, v, c.XfrmErrorNodeCount[k], c.TotalNodeCount))
		}
	}
	if c.EncWireguardNodeCount > 0 {
		builder.WriteString(fmt.Sprintf("Encryption: Wireguard (%d/%d nodes)\n", c.EncWireguardNodeCount, c.TotalNodeCount))
	}
	_, err := fmt.Println(builder.String())
	return err
}

func (n nodeStatus) printStatus(format string) error {
	if format == status.OutputJSON {
		return printJSONStatus(n)
	}

	builder := strings.Builder{}
	builder.WriteString(fmt.Sprintf("Node: %s\n", n.NodeName))
	builder.WriteString(fmt.Sprintf("Encryption: %s\n", n.EncryptionType))
	if n.IPsecKeysInUse > 0 {
		builder.WriteString(fmt.Sprintf("IPsec keys in use: %d\n", n.IPsecKeysInUse))
	}
	if n.IPsecMaxSeqNum != "" {
		builder.WriteString(fmt.Sprintf("IPsec highest Seq. Number: %s\n", n.IPsecMaxSeqNum))
	}
	if n.EncryptionType == "IPsec" {
		builder.WriteString(fmt.Sprintf("IPsec errors: %d\n", n.IPsecErrCount))
	}
	for k, v := range n.XfrmErrors {
		builder.WriteString(fmt.Sprintf("\t%s: %d\n", k, v))
	}
	_, err := fmt.Println(builder.String())
	return err
}

func printJSONStatus(v any) error {
	js, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		return err
	}
	fmt.Println(string(js))
	return nil
}
