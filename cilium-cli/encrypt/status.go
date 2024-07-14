// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package encrypt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/cilium/cilium/api/v1/models"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/status"
	"github.com/cilium/cilium-cli/utils/features"
)

// PrintEncryptStatus prints encryption status from all/specific cilium agent pods.
func (s *Encrypt) PrintEncryptStatus(ctx context.Context) error {
	ctx, cancelFn := context.WithTimeout(ctx, s.params.WaitDuration)
	defer cancelFn()

	pods, err := s.fetchCiliumPods(ctx)
	if err != nil {
		return err
	}

	nodeMap, err := s.fetchEncryptStatusConcurrently(ctx, pods)
	if err != nil {
		return err
	}

	ikProps, err := s.getIPsecKeyProps(ctx, len(pods))
	if err != nil {
		return err
	}

	if s.params.PerNodeDetails {
		return printPerNodeStatus(nodeMap, ikProps, s.params.Output)
	}

	cs, err := getClusterStatus(nodeMap, ikProps)
	if err != nil {
		return err
	}
	return printClusterStatus(cs, s.params.Output)
}

func (s *Encrypt) fetchEncryptStatusConcurrently(ctx context.Context, pods []corev1.Pod) (map[string]models.EncryptionStatus, error) {
	// res contains data returned from cilium pod
	type res struct {
		nodeName string
		status   models.EncryptionStatus
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

	// read from the channel, on error, store error and continue to next node
	var err error
	data := make(map[string]models.EncryptionStatus)
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

func (s *Encrypt) fetchEncryptStatusFromPod(ctx context.Context, pod corev1.Pod) (models.EncryptionStatus, error) {
	cmd := []string{"cilium", "encrypt", "status", "-o", "json"}
	output, err := s.client.ExecInPod(ctx, pod.Namespace, pod.Name, defaults.AgentContainerName, cmd)
	if err != nil {
		return models.EncryptionStatus{}, fmt.Errorf("failed to fetch encryption status from %s: %w", pod.Name, err)
	}
	encStatus, err := nodeStatusFromOutput(output.String())
	if err != nil {
		return models.EncryptionStatus{}, fmt.Errorf("failed to parse encryption status from %s: %w", pod.Name, err)
	}
	return encStatus, nil
}

func nodeStatusFromOutput(output string) (models.EncryptionStatus, error) {
	if !json.Valid([]byte(output)) {
		res, err := nodeStatusFromText(output)
		if err != nil {
			return models.EncryptionStatus{}, fmt.Errorf("failed to parse text: %w", err)
		}
		return res, nil
	}
	encStatus := models.EncryptionStatus{}
	if err := json.Unmarshal([]byte(output), &encStatus); err != nil {
		return models.EncryptionStatus{}, fmt.Errorf("failed to unmarshal json: %w", err)
	}
	return encStatus, nil
}

func nodeStatusFromText(str string) (models.EncryptionStatus, error) {
	res := models.EncryptionStatus{
		Ipsec: &models.IPsecStatus{
			DecryptInterfaces: make([]string, 0),
			XfrmErrors:        make(map[string]int64),
		},
		Wireguard: &models.WireguardStatus{
			Interfaces: make([]*models.WireguardInterface, 0),
		},
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
			res.Mode = value
		case "Max Seq. Number":
			res.Ipsec.MaxSeqNumber = value
		case "Decryption interface(s)":
			if value != "" {
				res.Ipsec.DecryptInterfaces = append(res.Ipsec.DecryptInterfaces, value)
			}
		case "Keys in use":
			keys, err := strconv.Atoi(value)
			if err != nil {
				return models.EncryptionStatus{}, fmt.Errorf("invalid number 'Keys in use' [%s]: %w", value, err)
			}
			res.Ipsec.KeysInUse = int64(keys)
		case "Errors":
			count, err := strconv.Atoi(value)
			if err != nil {
				return models.EncryptionStatus{}, fmt.Errorf("invalid number 'Errors' [%s]: %w", value, err)
			}
			res.Ipsec.ErrorCount = int64(count)
		default:
			count, err := strconv.Atoi(value)
			if err != nil {
				return models.EncryptionStatus{}, fmt.Errorf("invalid number '%s' [%s]: %w", key, value, err)
			}
			res.Ipsec.XfrmErrors[key] = int64(count)
		}
	}
	return res, nil
}

type ipsecKeyProps struct {
	perNode       bool
	expectedCount int
}

func (s *Encrypt) getIPsecKeyProps(ctx context.Context, nodeCount int) (ipsecKeyProps, error) {
	cm, err := s.client.GetConfigMap(ctx, s.params.CiliumNamespace, defaults.ConfigMapName, metav1.GetOptions{})
	if err != nil {
		return ipsecKeyProps{}, fmt.Errorf("unable get ConfigMap %q: %w", defaults.ConfigMapName, err)
	}

	fs := features.Set{}
	fs.ExtractFromConfigMap(cm)
	if !fs[features.IPsecEnabled].Enabled {
		return ipsecKeyProps{}, nil
	}

	key, err := s.readIPsecKey(ctx)
	if err != nil {
		return ipsecKeyProps{}, err
	}

	perNode := strings.Contains(key, "+")
	return ipsecKeyProps{
		perNode:       perNode,
		expectedCount: expectedIPsecKeyCount(nodeCount, fs, perNode),
	}, nil
}

func expectedIPsecKeyCount(ciliumPods int, fs features.Set, perNodeKey bool) int {
	if !perNodeKey {
		return 1
	}
	// IPsec key states for `local_cilium_internal_ip` and `remote_node_ip`
	xfrmStates := 2
	if fs[features.CiliumIPAMMode].Mode == "eni" || fs[features.CiliumIPAMMode].Mode == "azure" {
		xfrmStates++
	}
	if fs[features.IPv6].Enabled {
		// multiply by 2 because of dual state: IPv4 & IPv6
		xfrmStates *= 2
	}
	// subtract 1 to count remote nodes only
	return (ciliumPods - 1) * xfrmStates
}

func printPerNodeStatus(nodeMap map[string]models.EncryptionStatus, ikProps ipsecKeyProps, format string) error {
	for node, st := range nodeMap {
		if format == status.OutputJSON {
			var ns any = st
			if st.Mode == "IPsec" {
				ns = nodeStatus{
					EncryptionStatus:           st,
					IPsecPerNodeKey:            ikProps.perNode,
					IPsecExpectedKeyCount:      ikProps.expectedCount,
					IPsecKeyRotationInProgress: int64(ikProps.expectedCount) != st.Ipsec.KeysInUse,
				}
			}
			return printJSONStatus(ns)
		}

		builder := strings.Builder{}
		builder.WriteString(fmt.Sprintf("Node: %s\n", node))
		builder.WriteString(fmt.Sprintf("Encryption: %s\n", st.Mode))
		if st.Mode == "IPsec" {
			if st.Ipsec.KeysInUse > 0 {
				builder.WriteString(fmt.Sprintf("IPsec keys in use: %d\n", st.Ipsec.KeysInUse))
			}
			if st.Ipsec.MaxSeqNumber != "" {
				builder.WriteString(fmt.Sprintf("IPsec highest Seq. Number: %s\n", st.Ipsec.MaxSeqNumber))
			}
			builder.WriteString(fmt.Sprintf("IPsec expected key count: %d\n", ikProps.expectedCount))
			builder.WriteString(fmt.Sprintf("IPsec key rotation in progress: %t\n", int64(ikProps.expectedCount) != st.Ipsec.KeysInUse))
			builder.WriteString(fmt.Sprintf("IPsec per-node key: %t\n", ikProps.perNode))
			builder.WriteString(fmt.Sprintf("IPsec errors: %d\n", st.Ipsec.ErrorCount))
			for k, v := range st.Ipsec.XfrmErrors {
				builder.WriteString(fmt.Sprintf("\t%s: %d\n", k, v))
			}
		}
		_, err := fmt.Println(builder.String())
		return err
	}
	return nil
}

func getClusterStatus(nodeMap map[string]models.EncryptionStatus, ikProps ipsecKeyProps) (clusterStatus, error) {
	cs := clusterStatus{
		TotalNodeCount:          len(nodeMap),
		IPsecKeysInUseNodeCount: make(map[int64]int64),
		XfrmErrors:              make(map[string]int64),
		XfrmErrorNodeCount:      make(map[string]int64),
	}
	keyRotationInProgress := false
	for _, v := range nodeMap {
		if v.Mode == "Disabled" {
			cs.EncDisabledNodeCount++
			continue
		}
		if v.Mode == "Wireguard" {
			cs.EncWireguardNodeCount++
			continue
		}
		if v.Mode == "IPsec" {
			cs.EncIPsecNodeCount++
			cs.IPsecExpectedKeyCount = ikProps.expectedCount
			cs.IPsecPerNodeKey = ikProps.perNode
		}
		cs.IPsecKeysInUseNodeCount[v.Ipsec.KeysInUse]++
		maxSeqNum, err := maxSequenceNumber(v.Ipsec.MaxSeqNumber, cs.IPsecMaxSeqNum)
		if err != nil {
			return clusterStatus{}, err
		}
		cs.IPsecMaxSeqNum = maxSeqNum
		cs.IPsecErrCount += v.Ipsec.ErrorCount
		for k, e := range v.Ipsec.XfrmErrors {
			cs.XfrmErrors[k] += e
			cs.XfrmErrorNodeCount[k]++
		}
		if int64(ikProps.expectedCount) != v.Ipsec.KeysInUse {
			keyRotationInProgress = true
		}
	}
	cs.IPsecKeyRotationInProgress = keyRotationInProgress
	return cs, nil
}

func printClusterStatus(cs clusterStatus, format string) error {
	if format == status.OutputJSON {
		return printJSONStatus(cs)
	}

	builder := strings.Builder{}
	if cs.EncDisabledNodeCount > 0 {
		builder.WriteString(fmt.Sprintf("Encryption: Disabled (%d/%d nodes)\n", cs.EncDisabledNodeCount, cs.TotalNodeCount))
	}
	if cs.EncIPsecNodeCount > 0 {
		builder.WriteString(fmt.Sprintf("Encryption: IPsec (%d/%d nodes)\n", cs.EncIPsecNodeCount, cs.TotalNodeCount))
		if len(cs.IPsecKeysInUseNodeCount) > 0 {
			keys := make([]int64, 0, len(cs.IPsecKeysInUseNodeCount))
			for k := range cs.IPsecKeysInUseNodeCount {
				keys = append(keys, k)
			}
			sort.Slice(keys, func(i, j int) bool {
				return keys[i] < keys[j]
			})
			keyStrs := make([]string, 0, len(keys))
			for _, k := range keys {
				keyStrs = append(keyStrs, fmt.Sprintf("%d on %d/%d", k, cs.IPsecKeysInUseNodeCount[k], cs.TotalNodeCount))
			}
			builder.WriteString(fmt.Sprintf("IPsec keys in use: %s\n", strings.Join(keyStrs, ", ")))
		}
		builder.WriteString(fmt.Sprintf("IPsec highest Seq. Number: %s across all nodes\n", cs.IPsecMaxSeqNum))
		builder.WriteString(fmt.Sprintf("IPsec expected key count: %d\n", cs.IPsecExpectedKeyCount))
		builder.WriteString(fmt.Sprintf("IPsec key rotation in progress: %t\n", cs.IPsecKeyRotationInProgress))
		builder.WriteString(fmt.Sprintf("IPsec per-node key: %t\n", cs.IPsecPerNodeKey))
		builder.WriteString(fmt.Sprintf("IPsec errors: %d across all nodes\n", cs.IPsecErrCount))
		for k, v := range cs.XfrmErrors {
			builder.WriteString(fmt.Sprintf("\t%s: %d on %d/%d nodes\n", k, v, cs.XfrmErrorNodeCount[k], cs.TotalNodeCount))
		}
	}
	if cs.EncWireguardNodeCount > 0 {
		builder.WriteString(fmt.Sprintf("Encryption: Wireguard (%d/%d nodes)\n", cs.EncWireguardNodeCount, cs.TotalNodeCount))
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
