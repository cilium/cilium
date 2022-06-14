// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	. "github.com/cilium/cilium/api/v1/client/policy"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/command"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/iana"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/k8s"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/policy/trace"
)

const (
	defaultSecurityID = -1
)

var src, dst, dports []string
var srcIdentity, dstIdentity int64
var srcEndpoint, dstEndpoint, srcK8sPod, dstK8sPod, srcK8sYaml, dstK8sYaml string

// policyTraceCmd represents the policy_trace command
var policyTraceCmd = &cobra.Command{
	Use:   "trace ( -s <label context> | --src-identity <security identity> | --src-endpoint <endpoint ID> | --src-k8s-pod <namespace:pod-name> | --src-k8s-yaml <path to YAML file> ) ( -d <label context> | --dst-identity <security identity> | --dst-endpoint <endpoint ID> | --dst-k8s-pod <namespace:pod-name> | --dst-k8s-yaml <path to YAML file>) --dport <port>[/<protocol>]",
	Short: "Trace a policy decision",
	Long: `Verifies if the source is allowed to consume
destination. Source / destination can be provided as endpoint ID, security ID, Kubernetes Pod, YAML file, set of LABELs. LABEL is represented as
SOURCE:KEY[=VALUE].
dports can be can be for example: 80/tcp, 53 or 23/udp.
If multiple sources and / or destinations are provided, each source is tested whether there is a policy allowing traffic between it and each destination.
--src-k8s-pod and --dst-k8s-pod requires cilium-agent to be running with disable-endpoint-crd option set to "false".`,
	Deprecated: "the output is not correct for all policy types. Consider instead using https://app.networkpolicy.io\n",
	Run: func(cmd *cobra.Command, args []string) {

		srcSlices := [][]string{}
		dstSlices := [][]string{}
		var srcSlice, dstSlice []string
		var dPorts []*models.Port
		var err error

		if len(src) == 0 && srcIdentity == defaultSecurityID && srcEndpoint == "" && srcK8sPod == "" && srcK8sYaml == "" {
			Usagef(cmd, "Missing source argument")
		}

		if len(dst) == 0 && dstIdentity == defaultSecurityID && dstEndpoint == "" && dstK8sPod == "" && dstK8sYaml == "" {
			Usagef(cmd, "Missing destination argument")
		}

		if len(src) > 0 {
			srcSlices = append(srcSlices, src)
		}

		if len(dst) > 0 {
			dstSlices = append(dstSlices, dst)
		}

		if len(dports) == 0 {
			Usagef(cmd, "Missing destination port/proto")
		} else {
			dPorts, err = parseL4PortsSlice(dports)
			if err != nil {
				Fatalf("Invalid destination port: %s", err)
			}
		}

		// Parse security identities.
		if srcIdentity != defaultSecurityID {
			srcSlice = appendIdentityLabelsToSlice(srcSlice, identity.NumericIdentity(srcIdentity).StringID())
			srcSlices = append(srcSlices, srcSlice)
		}

		if dstIdentity != defaultSecurityID {
			dstSlice = appendIdentityLabelsToSlice(dstSlice, identity.NumericIdentity(dstIdentity).StringID())
			dstSlices = append(dstSlices, dstSlice)
		}

		// Parse endpoint IDs.
		if srcEndpoint != "" {
			srcSlice = appendEpLabelsToSlice(srcSlice, srcEndpoint)
			srcSlices = append(srcSlices, srcSlice)
		}

		if dstEndpoint != "" {
			dstSlice = appendEpLabelsToSlice(dstSlice, dstEndpoint)
			dstSlices = append(dstSlices, dstSlice)
		}

		// Parse pod names.
		if srcK8sPod != "" {
			id, err := getSecIDFromK8s(srcK8sPod)
			if err != nil {
				Fatalf("Cannot get security id from k8s pod name: %s", err)
			}
			srcSlice = appendIdentityLabelsToSlice(srcSlice, id)
			srcSlices = append(srcSlices, srcSlice)
		}

		if dstK8sPod != "" {
			id, err := getSecIDFromK8s(dstK8sPod)
			if err != nil {
				Fatalf("Cannot get security id from k8s pod name: %s", err)
			}
			dstSlice = appendIdentityLabelsToSlice(dstSlice, id)
			dstSlices = append(dstSlices, dstSlice)
		}

		// Parse provided YAML files.
		if srcK8sYaml != "" {
			srcYamlSlices, err := trace.GetLabelsFromYaml(srcK8sYaml)
			if err != nil {
				Fatalf("%s", err)
			}
			srcSlices = append(srcSlices, srcYamlSlices...)
		}

		if dstK8sYaml != "" {
			dstYamlSlices, err := trace.GetLabelsFromYaml(dstK8sYaml)
			if err != nil {
				Fatalf("%s", err)
			}
			dstSlices = append(dstSlices, dstYamlSlices...)
		}

		for _, v := range srcSlices {
			for _, w := range dstSlices {
				search := models.TraceSelector{
					From: &models.TraceFrom{
						Labels: v,
					},
					To: &models.TraceTo{
						Labels: w,
						Dports: dPorts,
					},
					Verbose: verbose,
				}

				params := NewGetPolicyResolveParams().WithTraceSelector(&search).WithTimeout(api.ClientTimeout)
				if scr, err := client.Policy.GetPolicyResolve(params); err != nil {
					Fatalf("Error while retrieving policy assessment result: %s\n", err)
				} else if command.OutputOption() {
					if err := command.PrintOutput(scr); err != nil {
						os.Exit(1)
					}
				} else if scr != nil && scr.Payload != nil {
					fmt.Println("----------------------------------------------------------------")
					fmt.Printf("%s\n", scr.Payload.Log)
					fmt.Printf("Final verdict: %s\n", strings.ToUpper(scr.Payload.Verdict))
				}
			}
		}

		fmt.Fprintf(os.Stderr, "\nWarning: Due to changes to the internal policy handling in Cilium, the above output may be incorrect in some cases. This command has been deprecated and is planned for removal in a future Cilium release.\n")
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
	policyTraceCmd.Flags().StringVarP(&srcK8sYaml, "src-k8s-yaml", "", "", "Path to YAML file for source")
	policyTraceCmd.Flags().StringVarP(&dstK8sYaml, "dst-k8s-yaml", "", "", "Path to YAML file for destination")
	command.AddOutputOption(policyTraceCmd)
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

	lbls := []string{}
	if ep.Status != nil && ep.Status.Identity != nil && ep.Status.Identity.Labels != nil {
		lbls = ep.Status.Identity.Labels
	}

	return append(labelSlice, lbls...)
}

func getSecIDFromK8s(podName string) (string, error) {
	fmtdPodName := endpointid.NewID(endpointid.PodNamePrefix, podName)
	_, _, err := endpointid.Parse(fmtdPodName)
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
	restConfig, err := k8s.CreateConfigFromAgentResponse(resp)
	if err != nil {
		return "", fmt.Errorf("unable to create rest configuration: %s", err)
	}
	ciliumK8sClient, err := clientset.NewForConfig(restConfig)
	if err != nil {
		return "", fmt.Errorf("unable to create k8s client: %s", err)
	}

	ep, err := ciliumK8sClient.CiliumV2().CiliumEndpoints(namespace).Get(context.TODO(), pod, meta_v1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("unable to get pod %s in namespace %s", pod, namespace)
	}

	if ep.Status.Identity == nil {
		return "", fmt.Errorf("cilium security identity"+
			" not set for pod %s in namespace %s", pod, namespace)
	}

	return strconv.Itoa(int(ep.Status.Identity.ID)), nil
}

// parseL4PortsSlice parses a given `slice` of strings. Each string should be in
// the form of `<port>[/<protocol>]`, where the `<port>` is an integer or a port name and
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
			protoStr = models.PortProtocolANY
		case 2:
			protoStr = strings.ToUpper(vSplit[1])
			switch protoStr {
			case models.PortProtocolTCP, models.PortProtocolUDP, models.PortProtocolSCTP, models.PortProtocolICMP, models.PortProtocolICMPV6, models.PortProtocolANY:
			default:
				return nil, fmt.Errorf("invalid protocol %q", protoStr)
			}
		default:
			return nil, fmt.Errorf("invalid format %q. Should be <port>[/<protocol>]", v)
		}
		var port uint16
		portStr := vSplit[0]
		if !iana.IsSvcName(portStr) {
			portUint64, err := strconv.ParseUint(portStr, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid port %q: %s", portStr, err)
			}
			port = uint16(portUint64)
			portStr = ""
		}
		l4 := &models.Port{
			Port:     port,
			Name:     portStr,
			Protocol: protoStr,
		}
		rules = append(rules, l4)
	}
	return rules, nil
}
