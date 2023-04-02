// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package api

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/utils/strings/slices"

	pb "github.com/cilium/cilium/api/v1/flow"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	ciliumLabels "github.com/cilium/cilium/pkg/labels"
)

// ContextIdentifier describes the identification method of a transmission or
// receiving context
type ContextIdentifier int

const (
	// ContextDisabled disables context identification
	ContextDisabled ContextIdentifier = iota
	// ContextIdentity uses the full set of identity labels for identification purposes
	ContextIdentity
	// ContextNamespace uses the namespace name for identification purposes
	ContextNamespace
	// ContextPod uses the namespace and pod name for identification purposes in the form of namespace/pod-name.
	ContextPod
	// ContextPodShort uses a short version of the pod name. It should
	// typically map to the deployment/replicaset name. Deprecated.
	ContextPodShort
	// ContextPodName uses the pod name for identification purposes
	ContextPodName
	// ContextDNS uses the DNS name for identification purposes
	ContextDNS
	// ContextIP uses the IP address for identification purposes
	ContextIP
	// ContextReservedIdentity uses reserved labels in the identity label list for identification
	// purpose. It uses "reserved:kube-apiserver" label if it's present in the identity label list.
	// Otherwise, it uses the first label in the identity label list with "reserved:" prefix.
	ContextReservedIdentity
	// ContextWorkloadName uses the pod's workload name for identification.
	ContextWorkloadName
	// ContextApp uses the pod's app label for identification.
	ContextApp
)

// ContextOptionsHelp is the help text for context options
const ContextOptionsHelp = `
 sourceContext             ::= identifier , { "|", identifier }
 destinationContext        ::= identifier , { "|", identifier }
 sourceEgressContext       ::= identifier , { "|", identifier }
 sourceIngressContext      ::= identifier , { "|", identifier }
 destinationEgressContext  ::= identifier , { "|", identifier }
 destinationIngressContext ::= identifier , { "|", identifier }
 labels                    ::= label , { ",", label }
 identifier             ::= identity | namespace | pod | pod-short | pod-name | dns | ip | reserved-identity | workload-name | app
 label                     ::= source_ip | source_pod | source_namespace | source_workload | source_app | destination_ip | destination_pod | destination_namespace | destination_workload | destination_app | traffic_direction
`

var (
	shortPodPattern    = regexp.MustCompile("^(.+?)(-[a-z0-9]+){1,2}$")
	kubeAPIServerLabel = ciliumLabels.LabelKubeAPIServer.String()
	// contextLabelsList defines available labels for the ContextLabels
	// ContextIdentifier and the order of those labels for GetLabelNames and GetLabelValues.
	contextLabelsList = []string{
		"source_ip",
		"source_pod",
		"source_namespace",
		"source_workload",
		"source_app",
		"destination_ip",
		"destination_pod",
		"destination_namespace",
		"destination_workload",
		"destination_app",
		"traffic_direction",
	}
	allowedContextLabels = newLabelsSet(contextLabelsList)

	podAppLabels = []string{
		// k8s recommend app label
		ciliumLabels.LabelSourceK8s + ":" + k8sConst.AppKubernetes + "/name",
		// legacy k8s app label
		ciliumLabels.LabelSourceK8s + ":" + "k8s-app",
		// app label that is often used before people realize there's a recommended
		// label
		ciliumLabels.LabelSourceK8s + ":" + "app",
	}
)

// String return the context identifier as string
func (c ContextIdentifier) String() string {
	switch c {
	case ContextDisabled:
		return "disabled"
	case ContextIdentity:
		return "identity"
	case ContextNamespace:
		return "namespace"
	case ContextPod:
		return "pod"
	case ContextPodShort:
		return "pod-short"
	case ContextDNS:
		return "dns"
	case ContextIP:
		return "ip"
	case ContextReservedIdentity:
		return "reserved-identity"
	case ContextWorkloadName:
		return "workload-name"
	case ContextApp:
		return "app"
	}
	return fmt.Sprintf("%d", c)
}

type ContextIdentifierList []ContextIdentifier

func (cs ContextIdentifierList) String() string {
	s := make([]string, 0, len(cs))
	for _, c := range cs {
		s = append(s, c.String())
	}
	return strings.Join(s, "|")
}

// ContextOptions is the set of options to define whether and how to include
// sending and/or receiving context information
type ContextOptions struct {
	// Destination is the destination context to include in metrics for both egress and ingress traffic
	Destination ContextIdentifierList
	// Destination is the destination context to include in metrics for egress traffic (overrides Destination)
	DestinationEgress ContextIdentifierList
	// Destination is the destination context to include in metrics for ingress traffic (overrides Destination)
	DestinationIngress ContextIdentifierList

	allDestinationCtx ContextIdentifierList

	// Source is the source context to include in metrics for both egress and ingress traffic
	Source ContextIdentifierList
	// Source is the source context to include in metrics for egress traffic (overrides Source)
	SourceEgress ContextIdentifierList
	// Source is the source context to include in metrics for ingress traffic (overrides Source)
	SourceIngress ContextIdentifierList

	allSourceCtx ContextIdentifierList

	// Labels is the full set of labels that have been allowlisted when using the
	// ContextLabels ContextIdentifier.
	Labels labelsSet
}

func parseContextIdentifier(s string) (ContextIdentifier, error) {
	switch strings.ToLower(s) {
	case "identity":
		return ContextIdentity, nil
	case "namespace":
		return ContextNamespace, nil
	case "pod":
		return ContextPod, nil
	case "pod-short":
		return ContextPodShort, nil
	case "pod-name":
		return ContextPodName, nil
	case "dns":
		return ContextDNS, nil
	case "ip":
		return ContextIP, nil
	case "reserved-identity":
		return ContextReservedIdentity, nil
	case "workload-name":
		return ContextWorkloadName, nil
	case "app":
		return ContextApp, nil
	default:
		return ContextDisabled, fmt.Errorf("unknown context '%s'", s)
	}
}

func parseContext(s string) (cs ContextIdentifierList, err error) {
	for _, v := range strings.Split(s, "|") {
		c, err := parseContextIdentifier(v)
		if err != nil {
			return nil, err
		}
		cs = append(cs, c)
	}

	return cs, nil
}

func parseLabels(s string) (labelsSet, error) {
	labels := strings.Split(s, ",")
	for _, label := range labels {
		if !allowedContextLabels.HasLabel(label) {
			return labelsSet{}, fmt.Errorf("invalid labelsContext value: %s", label)
		}
	}
	ls := newLabelsSet(labels)
	return ls, nil
}

// ParseContextOptions parses a set of options and extracts the context
// relevant options
func ParseContextOptions(options Options) (*ContextOptions, error) {
	o := &ContextOptions{}
	var err error
	for key, value := range options {
		switch strings.ToLower(key) {
		case "destinationcontext":
			o.Destination, err = parseContext(value)
			o.allDestinationCtx = append(o.allDestinationCtx, o.Destination...)
			if err != nil {
				return nil, err
			}
		case "destinationegresscontext":
			o.DestinationEgress, err = parseContext(value)
			o.allDestinationCtx = append(o.allDestinationCtx, o.DestinationEgress...)
			if err != nil {
				return nil, err
			}
		case "destinationingresscontext":
			o.DestinationIngress, err = parseContext(value)
			o.allDestinationCtx = append(o.allDestinationCtx, o.DestinationIngress...)
			if err != nil {
				return nil, err
			}
		case "sourcecontext":
			o.Source, err = parseContext(value)
			o.allSourceCtx = append(o.allSourceCtx, o.Source...)
			if err != nil {
				return nil, err
			}
		case "sourceegresscontext":
			o.SourceEgress, err = parseContext(value)
			o.allSourceCtx = append(o.allSourceCtx, o.SourceEgress...)
			if err != nil {
				return nil, err
			}
		case "sourceingresscontext":
			o.SourceIngress, err = parseContext(value)
			o.allSourceCtx = append(o.allSourceCtx, o.SourceIngress...)
			if err != nil {
				return nil, err
			}
		case "labelscontext":
			o.Labels, err = parseLabels(value)
			if err != nil {
				return nil, err
			}
		}
	}

	return o, nil
}

type labelsSet map[string]struct{}

func newLabelsSet(labels []string) labelsSet {
	m := make(map[string]struct{}, len(labels))
	for _, label := range labels {
		m[label] = struct{}{}
	}
	return labelsSet(m)
}

func (ls labelsSet) HasLabel(label string) bool {
	_, exists := ls[label]
	return exists
}

func (ls labelsSet) String() string {
	var b strings.Builder
	// output the labels in a consistent order
	for _, label := range contextLabelsList {
		if ls.HasLabel(label) {
			if b.Len() > 0 {
				b.WriteString(",")
			}
			b.WriteString(label)
		}
	}
	return b.String()
}

func labelsContext(invertSourceDestination bool, wantedLabels labelsSet, flow *pb.Flow) (outputLabels []string, err error) {
	source, destination := flow.GetSource(), flow.GetDestination()
	sourceIp, destinationIp := flow.GetIP().GetSource(), flow.GetIP().GetDestination()
	if invertSourceDestination {
		source, destination = flow.GetDestination(), flow.GetSource()
		sourceIp, destinationIp = flow.GetIP().GetDestination(), flow.GetIP().GetSource()
	}
	// Iterate over contextLabelsList so that the label order is stable,
	// otherwise GetLabelNames and GetLabelValues might be mismatched
	for _, label := range contextLabelsList {
		if wantedLabels.HasLabel(label) {
			var labelValue string
			switch label {
			case "source_ip":
				labelValue = sourceIp
			case "source_pod":
				labelValue = source.GetPodName()
			case "source_namespace":
				labelValue = source.GetNamespace()
			case "source_workload":
				if workloads := source.GetWorkloads(); len(workloads) != 0 {
					labelValue = workloads[0].Name
				}
			case "source_app":
				labelValue = getK8sAppFromLabels(source.GetLabels())
			case "destination_ip":
				labelValue = destinationIp
			case "destination_pod":
				labelValue = destination.GetPodName()
			case "destination_namespace":
				labelValue = destination.GetNamespace()
			case "destination_workload":
				if workloads := destination.GetWorkloads(); len(workloads) != 0 {
					labelValue = workloads[0].Name
				}
			case "destination_app":
				labelValue = getK8sAppFromLabels(destination.GetLabels())
			case "traffic_direction":
				direction := flow.GetTrafficDirection()
				if direction == pb.TrafficDirection_TRAFFIC_DIRECTION_UNKNOWN {
					labelValue = "unknown"
				} else {
					labelValue = strings.ToLower(direction.String())
				}
			default:
				// Label is in contextLabelsList but isn't handled in the switch
				// statement. Programmer error.
				return nil, fmt.Errorf("BUG: Label %s not mapped in labelsContext. Please report this bug to Cilium developers.", label)
			}
			outputLabels = append(outputLabels, labelValue)
		}
	}
	return outputLabels, nil
}

func shortenPodName(name string) string {
	return shortPodPattern.ReplaceAllString(name, "${1}")
}

func handleReservedIdentityLabels(lbls []string) string {
	// if reserved:kube-apiserver label is present, return it (instead of reserved:world, etc..)
	if slices.Contains(lbls, kubeAPIServerLabel) {
		return kubeAPIServerLabel
	}
	// else return the first reserved label.
	for _, label := range lbls {
		if strings.HasPrefix(label, ciliumLabels.LabelSourceReserved+":") {
			return label
		}
	}
	return ""
}

func getK8sAppFromLabels(labels []string) string {
	for _, label := range labels {
		for _, appLabel := range podAppLabels {
			if strings.HasPrefix(label, appLabel+"=") {
				l := ciliumLabels.ParseLabel(label)
				if l.Value != "" {
					return l.Value
				}
			}
		}
	}
	return ""
}

// GetLabelValues returns the values of the context relevant labels according
// to the configured options. The order of the values is the same as the order
// of the label names returned by GetLabelNames()
func (o *ContextOptions) GetLabelValues(flow *pb.Flow) (labels []string, err error) {
	return o.getLabelValues(false, flow)
}

// GetLabelValuesInvertSourceDestination is the same as GetLabelValues but the
// source and destination labels are inverted. This is primarily for metrics
// that leverage the response/return flows where the source and destination are
// swapped from the request flow.
func (o *ContextOptions) GetLabelValuesInvertSourceDestination(flow *pb.Flow) (labels []string, err error) {
	return o.getLabelValues(true, flow)
}

// getLabelValues returns the values of the context relevant labels according
// to the configured options. The order of the values is the same as the order
// of the label names returned by GetLabelNames(). If invert is true, the
// source and destination related labels are inverted.
func (o *ContextOptions) getLabelValues(invert bool, flow *pb.Flow) (labels []string, err error) {
	if len(o.Labels) != 0 {
		labelsContextLabels, err := labelsContext(invert, o.Labels, flow)
		if err != nil {
			return nil, err
		}
		labels = append(labels, labelsContextLabels...)
	}

	var sourceLabel string
	var sourceContextIdentifiers = o.Source
	if o.SourceIngress != nil && flow.GetTrafficDirection() == pb.TrafficDirection_INGRESS {
		sourceContextIdentifiers = o.SourceIngress
	} else if o.SourceEgress != nil && flow.GetTrafficDirection() == pb.TrafficDirection_EGRESS {
		sourceContextIdentifiers = o.SourceEgress
	}

	for _, contextID := range sourceContextIdentifiers {
		sourceLabel = getContextIDLabelValue(contextID, flow, true)
		// always use first non-empty context
		if sourceLabel != "" {
			break
		}
	}

	var destinationLabel string
	var destinationContextIdentifiers = o.Destination
	if o.DestinationIngress != nil && flow.GetTrafficDirection() == pb.TrafficDirection_INGRESS {
		destinationContextIdentifiers = o.DestinationIngress
	} else if o.DestinationEgress != nil && flow.GetTrafficDirection() == pb.TrafficDirection_EGRESS {
		destinationContextIdentifiers = o.DestinationEgress
	}
	for _, contextID := range destinationContextIdentifiers {
		destinationLabel = getContextIDLabelValue(contextID, flow, false)
		// always use first non-empty context
		if destinationLabel != "" {
			break
		}
	}

	if invert {
		sourceLabel, destinationLabel = destinationLabel, sourceLabel
	}
	if len(o.Source) != 0 {
		labels = append(labels, sourceLabel)
	}
	if len(o.Destination) != 0 {
		labels = append(labels, destinationLabel)
	}
	return
}

func getContextIDLabelValue(contextID ContextIdentifier, flow *pb.Flow, source bool) string {
	var ep *pb.Endpoint
	if source {
		ep = flow.GetSource()
	} else {
		ep = flow.GetDestination()
	}
	var labelValue string
	switch contextID {
	case ContextNamespace:
		labelValue = ep.GetNamespace()
	case ContextIdentity:
		labelValue = strings.Join(ep.GetLabels(), ",")
	case ContextPod:
		labelValue = ep.GetPodName()
		if ep.GetNamespace() != "" {
			labelValue = ep.GetNamespace() + "/" + labelValue
		}
	case ContextPodShort:
		labelValue = shortenPodName(ep.GetPodName())
		if ep.GetNamespace() != "" {
			labelValue = ep.GetNamespace() + "/" + labelValue
		}
	case ContextPodName:
		labelValue = ep.GetPodName()
	case ContextDNS:
		if source {
			labelValue = strings.Join(flow.GetSourceNames(), ",")
		} else {
			labelValue = strings.Join(flow.GetDestinationNames(), ",")
		}
	case ContextIP:
		if source {
			labelValue = flow.GetIP().GetSource()
		} else {
			labelValue = flow.GetIP().GetDestination()
		}
	case ContextReservedIdentity:
		labelValue = handleReservedIdentityLabels(ep.GetLabels())

	case ContextWorkloadName:
		if workloads := ep.GetWorkloads(); len(workloads) != 0 {
			labelValue = workloads[0].Name
		}
	case ContextApp:
		labelValue = getK8sAppFromLabels(ep.GetLabels())
	}
	return labelValue
}

// GetLabelNames returns a slice of label names required to fulfil the
// configured context description requirements
func (o *ContextOptions) GetLabelNames() (labels []string) {
	if len(o.Labels) != 0 {
		// We must iterate over contextLabelsList to ensure the order of the label
		// names the same order as label values in GetLabelValues.
		for _, label := range contextLabelsList {
			if o.Labels.HasLabel(label) {
				labels = append(labels, label)
			}
		}
	}

	if len(o.Source) != 0 {
		labels = append(labels, "source")
	}

	if len(o.Destination) != 0 {
		labels = append(labels, "destination")
	}

	return
}

// Status returns the configuration status of context options suitable for use
// with Handler.Status
func (o *ContextOptions) Status() string {
	var status []string
	if len(o.Labels) != 0 {
		status = append(status, "labels="+o.Labels.String())
	}

	if len(o.Source) != 0 {
		status = append(status, "source="+o.Source.String())
	}

	if len(o.Destination) != 0 {
		status = append(status, "destination="+o.Destination.String())
	}

	sort.Strings(status)

	return strings.Join(status, ",")
}

func (o *ContextOptions) DeleteMetricsAssociatedWithPod(name string, namespace string, vec *prometheus.MetricVec) {
	for _, contextID := range o.allSourceCtx {
		if contextID == ContextPod {
			vec.DeletePartialMatch(prometheus.Labels{
				"source": namespace + "/" + name,
			})
		}
	}
	for _, contextID := range o.allDestinationCtx {
		if contextID == ContextPod {
			vec.DeletePartialMatch(prometheus.Labels{
				"destination": namespace + "/" + name,
			})
		}
	}

	if o.Labels.HasLabel("source_pod") && o.Labels.HasLabel("source_namespace") {
		vec.DeletePartialMatch(prometheus.Labels{
			"source_namespace": namespace,
			"source_pod":       name,
		})
	}
	if o.Labels.HasLabel("destination_pod") && o.Labels.HasLabel("destination_namespace") {
		vec.DeletePartialMatch(prometheus.Labels{
			"destination_namespace": namespace,
			"destination_pod":       name,
		})
	}
}
