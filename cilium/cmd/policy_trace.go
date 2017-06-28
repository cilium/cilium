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
	"fmt"
	"strconv"
	"strings"

	. "github.com/cilium/cilium/api/v1/client/policy"
	"github.com/cilium/cilium/api/v1/models"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/spf13/cobra"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	defaultSecurityID = -1
)

var src, dst, dports []string
var srcIdentity, dstIdentity int64
var srcEndpoint, dstEndpoint, srcK8sPod, dstK8sPod string
var verbose bool

// policyTraceCmd represents the policy_trace command
var policyTraceCmd = &cobra.Command{
	Use:   "trace ( -s <label context> | --src-identity <security identity> | --src-endpoint <endpoint ID> | --src-k8s-pod <namespace:pod-name> ) ( -d <label context> | --dst-identity <security identity> | --dst-endpoint <endpoint ID> | --dst-k8s-pod <namespace:pod-name> ) [--dport <port>[/<protocol>]",
	Short: "Trace a policy decision",
	Long: `Verifies if source ID or LABEL(s) is allowed to consume
destination ID or LABEL(s). LABEL is represented as
SOURCE:KEY[=VALUE].
dports can be can be for example: 80/tcp, 53 or 23/udp.`,
	Run: func(cmd *cobra.Command, args []string) {

		var srcSlice, dstSlice, dports []string
		var dPorts []*models.Port
		var err error

		if len(src) == 0 && srcIdentity == defaultSecurityID && srcEndpoint == "" && srcK8sPod == "" {
			Usagef(cmd, "Missing source argument")
		}

		if len(dst) == 0 && dstIdentity == defaultSecurityID && dstEndpoint == "" && dstK8sPod == "" {
			Usagef(cmd, "Missing destination argument")
		}

		// Parse provided labels
		if len(src) > 0 {
			srcSlice, err = parseLabels(src)
			if err != nil {
				Fatalf("Invalid source: %s", err)
			}
		}

		if len(dst) > 0 {
			dstSlice, err = parseLabels(dst)
			if err != nil {
				Fatalf("Invalid destination: %s", err)
			}

			dPorts, err = parseL4PortsSlice(dports)
			if err != nil {
				Fatalf("Invalid destination port: %s", err)
			}
		}

		// Parse security identities.
		if srcIdentity != defaultSecurityID {
			srcSlice = appendIdentityLabelsToSlice(srcSlice, policy.NumericIdentity(srcIdentity).StringID())
		}
		if dstIdentity != defaultSecurityID {
			dstSlice = appendIdentityLabelsToSlice(dstSlice, policy.NumericIdentity(dstIdentity).StringID())
		}

		// Parse endpoint IDs.
		if srcEndpoint != "" {
			srcSlice = appendEpLabelsToSlice(srcSlice, srcEndpoint)
		}

		if dstEndpoint != "" {
			dstSlice = appendEpLabelsToSlice(dstSlice, dstEndpoint)
		}

		// Parse pod names.
		if srcK8sPod != "" {
			id, err := getSecIDFromK8s(srcK8sPod)
			if err != nil {
				Fatalf("Cannot get security id from k8s pod name: %s", err)
			}
			srcSlice = appendIdentityLabelsToSlice(srcSlice, id)
		}

		if dstK8sPod != "" {
			id, err := getSecIDFromK8s(dstK8sPod)
			if err != nil {
				Fatalf("Cannot get security id from k8s pod name: %s", err)
			}
			dstSlice = appendIdentityLabelsToSlice(dstSlice, id)
		}

		search := models.IdentityContext{
			From:    srcSlice,
			To:      dstSlice,
			Dports:  dPorts,
			Verbose: verbose,
		}

		params := NewGetPolicyResolveParams().WithIdentityContext(&search)
		if scr, err := client.Policy.GetPolicyResolve(params); err != nil {
			Fatalf("Error while retrieving policy assessment result: %s\n", err)
		} else if scr != nil && scr.Payload != nil {
			fmt.Printf("%s\n", scr.Payload.Log)
			fmt.Printf("Verdict: %s\n", scr.Payload.Verdict)
		}
	},
}

func init() {
	policyCmd.AddCommand(policyTraceCmd)
	policyTraceCmd.Flags().StringSliceVarP(&src, "src", "s", []string{}, "Source label context")
	policyTraceCmd.Flags().StringSliceVarP(&dst, "dst", "d", []string{}, "Destination label context")
	policyTraceCmd.Flags().StringSliceVarP(&dports, "dport", "", []string{}, "L4 destination port to search on outgoing traffic of the source label context and on incoming traffic of the destination label context")
	policyTraceCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Set tracing to TRACE_VERBOSE")
	policyTraceCmd.Flags().Int64VarP(&srcIdentity, "src-identity", "", defaultSecurityID, "Source identity")
	policyTraceCmd.Flags().Int64VarP(&dstIdentity, "dst-identity", "", defaultSecurityID, "Destination identity")
	policyTraceCmd.Flags().StringVarP(&srcEndpoint, "src-endpoint", "", "", "Source endpoint")
	policyTraceCmd.Flags().StringVarP(&dstEndpoint, "dst-endpoint", "", "", "Destination endpoint")
	policyTraceCmd.Flags().StringVarP(&srcK8sPod, "src-k8s-pod", "", "", "Source k8s pod ([namespace:]podname)")
	policyTraceCmd.Flags().StringVarP(&dstK8sPod, "dst-k8s-pod", "", "", "Destination k8s pod ([namespace:]podname)")
}

func appendIdentityLabelsToSlice(labelSlice []string, secID string) []string {
	resp, err := client.IdentityGet(secID)
	if err != nil {
		Fatalf("%s", err)
	}
	return append(labelSlice, resp.Labels...)
}

func appendEpLabelsToSlice(labelSlice []string, epID string) []string {
	ep, err := client.EndpointGet(epID)
	if err != nil {
		Fatalf("Cannot get endpoint corresponding to identifier %s: %s\n", epID, err)
	}
	return append(labelSlice, ep.Identity.Labels...)
}

func parseLabels(slice []string) ([]string, error) {
	if len(slice) == 0 {
		return nil, fmt.Errorf("No labels provided")
	}
	return slice, nil
}

func getSecIDFromK8s(podName string) (string, error) {
	fmtdPodName := endpoint.NewID(endpoint.PodNamePrefix, podName)
	_, _, err := endpoint.ValidateID(fmtdPodName)
	if err != nil {
		Fatalf("Cannot parse pod name \"%s\": %s", fmtdPodName, err)
	}

	splitPodName := strings.Split(podName, ":")
	if len(splitPodName) < 2 {
		Fatalf("Improper identifier of pod provided; should be <namespace>:<pod name>")
	}
	namespace := splitPodName[0]
	pod := splitPodName[1]

	// The configuration for the Daemon contains the information needed to access the Kubernetes API.
	resp, err := client.ConfigGet()
	if err != nil {
		Fatalf("Error while retrieving configuration: %s", err)
	}
	k8sEndpoint := resp.K8sEndpoint
	k8sConfig := resp.K8sConfiguration
	restConfig, err := k8s.CreateConfig(k8sEndpoint, k8sConfig)
	if err != nil {
		return "", fmt.Errorf("unable to create rest configuration: %s", err)
	}
	k8sClient, err := k8s.CreateClient(restConfig)
	if err != nil {
		return "", fmt.Errorf("unable to create k8s client: %s", err)
	}

	p, err := k8sClient.CoreV1().Pods(namespace).Get(pod, meta_v1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("unable to get pod %s in namespace %s", namespace, pod)
	}

	secID := p.GetAnnotations()[common.CiliumIdentityAnnotation]
	if secID == "" {
		return "", fmt.Errorf("cilium-identity annotation not set for pod %s in namespace %s", namespace, pod)
	}

	return secID, nil
}

// parseL4PortsSlice parses a given `slice` of strings. Each string should be in
// the form of `<port>[/<protocol>]`, where the `<port>` in an integer and an
// `<protocol>` is an optional layer 4 protocol `tcp` or `udp`. In case
// `protocol` is not present, or is set to `any`, the parsed port will be set to
// `models.PortProtocolAny`.
func parseL4PortsSlice(slice []string) ([]*models.Port, error) {
	rules := []*models.Port{}
	for _, v := range slice {
		vSplit := strings.Split(v, "/")
		var protoStr string
		switch len(vSplit) {
		case 1:
			protoStr = models.PortProtocolAny
		case 2:
			protoStr = strings.ToLower(vSplit[1])
			switch protoStr {
			case models.PortProtocolTCP, models.PortProtocolUDP, models.PortProtocolAny:
			default:
				return nil, fmt.Errorf("invalid protocol %q", protoStr)
			}
		default:
			return nil, fmt.Errorf("invalid format %q. Should be <port>[/<protocol>]", v)
		}
		portStr := vSplit[0]
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %s", portStr, err)
		}
		l4 := &models.Port{
			Port:     uint16(port),
			Protocol: protoStr,
		}
		rules = append(rules, l4)
	}
	return rules, nil
}
