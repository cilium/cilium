// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package encrypt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/blang/semver/v4"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/cilium-cli/status"
	"github.com/cilium/cilium/cilium-cli/utils/features"
	"github.com/cilium/cilium/pkg/versioncheck"
)

// PrintEncryptStatus prints encryption status from all/specific cilium agent pods.
func (s *Encrypt) PrintEncryptStatus(ctx context.Context) error {
	ctx, cancelFn := context.WithTimeout(ctx, s.params.WaitDuration)
	defer cancelFn()

	pods, err := s.fetchCiliumPods(ctx)
	if err != nil {
		return err
	}

	ciliumVersion, err := s.checkAndGetCiliumVersion(ctx, pods)
	if err != nil {
		return err
	}

	cm, err := s.client.GetConfigMap(ctx, s.params.CiliumNamespace, defaults.ConfigMapName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("unable get ConfigMap %q: %w", defaults.ConfigMapName, err)
	}

	nodeMap, err := s.fetchEncryptStatusConcurrently(ctx, pods)
	if err != nil {
		return err
	}

	expectedKeyCount, err := ipsecExpectedKeyCount(*ciliumVersion, cm, len(pods))
	if err != nil {
		return err
	}

	if s.params.PerNodeDetails {
		return printPerNodeStatus(nodeMap, expectedKeyCount, s.params.Output)
	}

	cs, err := getClusterStatus(nodeMap, expectedKeyCount)
	if err != nil {
		return err
	}
	return printClusterStatus(cs, s.params.Output)
}

func (s *Encrypt) checkAndGetCiliumVersion(ctx context.Context, pods []corev1.Pod) (*semver.Version, error) {
	if len(pods) == 0 {
		return nil, errors.New("unable to find Cilium pods")
	}

	version, err := s.client.GetCiliumVersion(ctx, &pods[0])
	if err != nil {
		return nil, fmt.Errorf("unable to get Cilium version: %w", err)
	}

	if versioncheck.MustCompile("<1.18.0")(*version) {
		return nil, fmt.Errorf("Cilium version is too old: %s (command is supported since 1.18)", version.String())
	}
	return version, nil
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
	for line := range strings.SplitSeq(str, "\n") {
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

func ipsecExpectedKeyCount(ciliumVersion semver.Version, cm *corev1.ConfigMap, nodeCount int) (int, error) {
	fs := features.Set{}
	fs.ExtractFromConfigMap(cm)
	fs.ExtractFromVersionedConfigMap(ciliumVersion, cm)
	if !fs[features.IPsecEnabled].Enabled {
		return 0, nil
	}

	// We have two keys per node, per direction, per IP family.
	expectedKeys := (nodeCount - 1) * 2
	if fs[features.Tunnel].Enabled {
		// If running in tunneling mode, then we have twice the amount of states
		// and keys to handle encrypted overlay traffic.
		expectedKeys *= 2
	}
	if fs[features.IPv6].Enabled {
		// multiply by 2 because of dual stack: IPv4 & IPv6
		expectedKeys *= 2
	}
	return expectedKeys, nil
}

func printPerNodeStatus(nodeMap map[string]models.EncryptionStatus, expectedKeyCount int, format string) error {
	for node, st := range nodeMap {
		if format == status.OutputJSON {
			var ns any = st
			if st.Mode == "IPsec" {
				ns = nodeStatus{
					EncryptionStatus:           st,
					IPsecExpectedKeyCount:      expectedKeyCount,
					IPsecKeyRotationInProgress: int64(expectedKeyCount) != st.Ipsec.KeysInUse,
				}
			}
			if err := printJSONStatus(ns); err != nil {
				return err
			}
			continue
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
			builder.WriteString(fmt.Sprintf("IPsec expected key count: %d\n", expectedKeyCount))
			builder.WriteString(fmt.Sprintf("IPsec key rotation in progress: %t\n", int64(expectedKeyCount) != st.Ipsec.KeysInUse))
			builder.WriteString(fmt.Sprintf("IPsec errors: %d\n", st.Ipsec.ErrorCount))
			for k, v := range st.Ipsec.XfrmErrors {
				builder.WriteString(fmt.Sprintf("\t%s: %d\n", k, v))
			}
		}
		if _, err := fmt.Println(builder.String()); err != nil {
			return err
		}
	}
	return nil
}

func getClusterStatus(nodeMap map[string]models.EncryptionStatus, expectedKeyCount int) (clusterStatus, error) {
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
			cs.IPsecExpectedKeyCount = expectedKeyCount
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
		if int64(expectedKeyCount) != v.Ipsec.KeysInUse {
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
			keys := slices.Sorted(maps.Keys(cs.IPsecKeysInUseNodeCount))
			keyStrs := make([]string, 0, len(keys))
			for _, k := range keys {
				keyStrs = append(keyStrs, fmt.Sprintf("%d on %d/%d", k, cs.IPsecKeysInUseNodeCount[k], cs.TotalNodeCount))
			}
			builder.WriteString(fmt.Sprintf("IPsec keys in use: %s\n", strings.Join(keyStrs, ", ")))
		}
		builder.WriteString(fmt.Sprintf("IPsec highest Seq. Number: %s across all nodes\n", cs.IPsecMaxSeqNum))
		builder.WriteString(fmt.Sprintf("IPsec expected key count: %d\n", cs.IPsecExpectedKeyCount))
		builder.WriteString(fmt.Sprintf("IPsec key rotation in progress: %t\n", cs.IPsecKeyRotationInProgress))
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
