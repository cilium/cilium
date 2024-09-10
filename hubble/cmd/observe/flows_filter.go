// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package observe

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/pflag"
	"google.golang.org/protobuf/proto"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

type (
	flagName  = string
	flagDesc  = string
	shortName = string
)

type filterTracker struct {
	// the resulting filter will be `left OR right`
	left, right *flowpb.FlowFilter

	// namespaces set through flags, will be applied to the pod and/or service
	// filter when the flow filters are materialized.
	ns, srcNs, dstNs namespaceModifier
	// which values were touched by the user. This is important because all of
	// the defaults need to be wiped the first time user touches a []string
	// value.
	changed []string
}

func (f filterTracker) String() string {
	ff := f.flowFilters()
	if bs, err := json.Marshal(ff); err == nil {
		return fmt.Sprintf("%v", string(bs))
	}
	return fmt.Sprintf("%v", ff)
}

func (f *filterTracker) add(name string) bool {
	for _, exists := range f.changed {
		if name == exists {
			return false
		}
	}

	// wipe the existing values if this is the first time usage of this
	// flag, otherwise defaults creep into the final set.
	f.changed = append(f.changed, name)

	return true
}

func (f *filterTracker) apply(update func(*flowpb.FlowFilter)) {
	f.applyLeft(update)
	f.applyRight(update)
}

func (f *filterTracker) applyLeft(update func(*flowpb.FlowFilter)) {
	if f.left == nil {
		f.left = &flowpb.FlowFilter{}
	}
	update(f.left)
}

func (f *filterTracker) applyRight(update func(*flowpb.FlowFilter)) {
	if f.right == nil {
		f.right = &flowpb.FlowFilter{}
	}
	update(f.right)
}

type namespaceModifier []string

func (nm namespaceModifier) applySrc(ff *flowpb.FlowFilter) {
	if len(ff.GetSourcePod()) == 0 && len(ff.GetSourceService()) == 0 {
		ff.SourcePod = []string{""}
	}
	ff.SourcePod = addNamespacesToFilter(ff.GetSourcePod(), nm)
	ff.SourceService = addNamespacesToFilter(ff.GetSourceService(), nm)
}

func (nm namespaceModifier) applyDest(ff *flowpb.FlowFilter) {
	if len(ff.GetDestinationPod()) == 0 && len(ff.GetDestinationService()) == 0 {
		ff.DestinationPod = []string{""}
	}
	ff.DestinationPod = addNamespacesToFilter(ff.GetDestinationPod(), nm)
	ff.DestinationService = addNamespacesToFilter(ff.GetDestinationService(), nm)
}

func (nm namespaceModifier) conflicts(names []string) error {
	for _, ns := range nm {
		for _, name := range names {
			if nn := namespaceFromName(name); nn != "" && nn != ns {
				return fmt.Errorf("namespace conflict: %q does not contain %q", ns, name)
			}
		}
	}
	return nil
}

func namespaceFromName(name string) string {
	namespacedName := strings.Split(name, "/")
	if len(namespacedName) > 1 {
		return namespacedName[0]
	}
	return ""
}

func addNamespacesToFilter(filter []string, ns []string) []string {
	if len(ns) == 0 || len(filter) == 0 {
		return filter
	}

	res := []string{}
	for i := range filter {
		if strings.Contains(filter[i], "/") {
			res = append(res, filter[i])
			continue
		}
		for j := range ns {
			res = append(res, fmt.Sprintf("%s/%s", ns[j], filter[i]))
		}
	}
	return res
}

func (f *filterTracker) flowFilters() []*flowpb.FlowFilter {
	if f.left == nil && f.right == nil &&
		len(f.ns) == 0 && len(f.dstNs) == 0 && len(f.srcNs) == 0 {
		return nil
	}
	if f.left == nil {
		f.left = &flowpb.FlowFilter{}
	}
	if f.right == nil {
		f.right = &flowpb.FlowFilter{}
	}

	if len(f.dstNs) > 0 {
		f.dstNs.applyDest(f.left)
		f.dstNs.applyDest(f.right)
	}
	if len(f.srcNs) > 0 {
		f.srcNs.applySrc(f.left)
		f.srcNs.applySrc(f.right)
	}
	if len(f.ns) > 0 {
		f.ns.applySrc(f.left)
		f.ns.applyDest(f.right)
	}

	if proto.Equal(f.left, f.right) {
		return []*flowpb.FlowFilter{f.left}
	}
	return []*flowpb.FlowFilter{f.left, f.right}
}

// Implements pflag.Value
type flowFilter struct {
	whitelist *filterTracker
	blacklist *filterTracker

	// tracks if the next dispatched filter is going into blacklist or
	// whitelist. Blacklist is only triggered by `--not` and has to be set for
	// every blacklisted filter, i.e. `--not pod-ip 127.0.0.1 --not pod-ip
	// 2.2.2.2`.
	blacklisting bool

	conflicts [][]string // conflict config
}

func newFlowFilter() *flowFilter {
	return &flowFilter{
		conflicts: [][]string{
			{"from-fqdn", "from-ip", "ip", "fqdn", "from-namespace", "namespace", "from-all-namespaces", "all-namespaces"},
			{"from-fqdn", "from-ip", "ip", "fqdn", "from-pod", "pod"},
			{"to-fqdn", "to-ip", "ip", "fqdn", "to-namespace", "namespace", "to-all-namespaces", "all-namespaces"},
			{"to-fqdn", "to-ip", "ip", "fqdn", "to-pod", "pod"},
			{"to-pod", "namespace", "all-namespaces"},
			{"from-pod", "namespace", "all-namespaces"},
			{"to-service", "namespace", "all-namespaces"},
			{"from-service", "namespace", "all-namespaces"},
			{"snat-ip"},
			{"label", "from-label"},
			{"label", "to-label"},
			{"service", "from-service"},
			{"service", "to-service"},
			{"verdict"},
			{"drop-reason-desc"},
			{"type"},
			{"http-status"},
			{"http-method"},
			{"http-path"},
			{"http-url"},
			{"http-header"},
			{"protocol"},
			{"port", "to-port"},
			{"port", "from-port"},
			{"identity", "to-identity"},
			{"identity", "from-identity"},
			{"workload", "to-workload"},
			{"workload", "from-workload"},
			{"node-name", "cluster"},
			{"node-label"},
			{"tcp-flags"},
			{"uuid"},
			{"traffic-direction"},
			{"cel-expression"},
		},
	}
}

func (of *flowFilter) checkConflict(t *filterTracker) error {
	// check for conflicts
	for _, group := range of.conflicts {
		for _, flag := range group {
			if slices.Contains(t.changed, flag) {
				for _, conflict := range group {
					if flag != conflict && slices.Contains(t.changed, conflict) {
						return fmt.Errorf(
							"filters --%s and --%s cannot be combined",
							flag, conflict,
						)
					}
				}
			}
		}
	}
	return nil
}

// checkInconsistentNamespaces checks if the namespaces in pods and services make sense
// i.e. it checks that we don't request a service in one namespace with pods in another namespace
func checkInconsistentNamespaces(pods, services []string) error {
	for _, pod := range pods {
		podNs := namespaceFromName(pod)
		if podNs == "" {
			continue
		}
		for _, svc := range services {
			if ns := namespaceFromName(svc); podNs != ns {
				return fmt.Errorf("namespace of service %q conflict with pod %q", svc, podNs)
			}
		}
	}
	return nil
}

// checkNamespaceConflicts checks for conflicts in namespaces, pods and services
func (t *filterTracker) checkNamespaceConflicts(ff *flowpb.FlowFilter) error {
	if ff == nil {
		return nil
	}
	return errors.Join(t.ns.conflicts(ff.GetSourcePod()),
		t.ns.conflicts(ff.GetSourceService()),
		t.ns.conflicts(ff.GetDestinationPod()),
		t.ns.conflicts(ff.GetDestinationService()),
		t.srcNs.conflicts(ff.GetSourcePod()),
		t.srcNs.conflicts(ff.GetSourceService()),
		t.dstNs.conflicts(ff.GetDestinationPod()),
		t.dstNs.conflicts(ff.GetDestinationService()),
		checkInconsistentNamespaces(ff.GetSourcePod(), ff.GetSourceService()),
		checkInconsistentNamespaces(ff.GetDestinationPod(), ff.GetDestinationService()),
	)
}

func parseTCPFlags(val string) (*flowpb.TCPFlags, error) {
	flags := &flowpb.TCPFlags{}
	s := strings.Split(val, ",")
	for _, f := range s {
		switch strings.ToUpper(f) {
		case "SYN":
			flags.SYN = true
		case "FIN":
			flags.FIN = true
		case "RST":
			flags.RST = true
		case "PSH":
			flags.PSH = true
		case "ACK":
			flags.ACK = true
		case "URG":
			flags.URG = true
		case "ECE":
			flags.ECE = true
		case "CWR":
			flags.CWR = true
		case "NS":
			flags.NS = true
		default:
			return nil, fmt.Errorf("unknown tcp flag: %s", f)
		}
	}
	return flags, nil
}

func ipVersion(v string) flowpb.IPVersion {
	switch strings.ToLower(v) {
	case "4", "v4", "ipv4", "ip4":
		return flowpb.IPVersion_IPv4
	case "6", "v6", "ipv6", "ip6":
		return flowpb.IPVersion_IPv6
	}
	return flowpb.IPVersion_IP_NOT_USED
}

func (of *flowFilter) Set(name, val string, track bool) error {
	// --not simply toggles the destination of the next filter into blacklist
	if name == "not" {
		if of.blacklisting {
			return errors.New("consecutive --not statements")
		}
		of.blacklisting = true
		return nil
	}

	if of.blacklisting {
		// --not only applies to a single filter so we turn off blacklisting
		of.blacklisting = false

		// lazy init blacklist
		if of.blacklist == nil {
			of.blacklist = &filterTracker{
				changed: []string{},
			}
		}
		return of.set(of.blacklist, name, val, track)
	}

	// lazy init whitelist
	if of.whitelist == nil {
		of.whitelist = &filterTracker{
			changed: []string{},
		}
	}

	return of.set(of.whitelist, name, val, track)
}

// agentEventSubtypes are the valid agent event sub-types. This map is
// necessary because the sub-type strings in monitorAPI.AgentNotifications
// contain upper-case characters and spaces which are inconvenient to pass as
// CLI filter arguments.
var agentEventSubtypes = map[string]monitorAPI.AgentNotification{
	"unspecified":                 monitorAPI.AgentNotifyUnspec,
	"message":                     monitorAPI.AgentNotifyGeneric,
	"agent-started":               monitorAPI.AgentNotifyStart,
	"policy-updated":              monitorAPI.AgentNotifyPolicyUpdated,
	"policy-deleted":              monitorAPI.AgentNotifyPolicyDeleted,
	"endpoint-regenerate-success": monitorAPI.AgentNotifyEndpointRegenerateSuccess,
	"endpoint-regenerate-failure": monitorAPI.AgentNotifyEndpointRegenerateFail,
	"endpoint-created":            monitorAPI.AgentNotifyEndpointCreated,
	"endpoint-deleted":            monitorAPI.AgentNotifyEndpointDeleted,
	"ipcache-upserted":            monitorAPI.AgentNotifyIPCacheUpserted,
	"ipcache-deleted":             monitorAPI.AgentNotifyIPCacheDeleted,
	"service-upserted":            monitorAPI.AgentNotifyServiceUpserted,
	"service-deleted":             monitorAPI.AgentNotifyServiceDeleted,
}

func (of *flowFilter) set(f *filterTracker, name, val string, track bool) error {
	// track the change if this is non-default user operation
	wipe := false
	if track {
		wipe = f.add(name)

		if err := of.checkConflict(f); err != nil {
			return err
		}
	}

	switch name {
	// flow identifier filter
	case "uuid":
		f.apply(func(f *flowpb.FlowFilter) {
			f.Uuid = append(f.GetUuid(), val)
		})
	// fqdn filters
	case "fqdn":
		f.applyLeft(func(f *flowpb.FlowFilter) {
			f.SourceFqdn = append(f.GetSourceFqdn(), val)
		})
		f.applyRight(func(f *flowpb.FlowFilter) {
			f.DestinationFqdn = append(f.GetDestinationFqdn(), val)
		})
	case "from-fqdn":
		f.apply(func(f *flowpb.FlowFilter) {
			f.SourceFqdn = append(f.GetSourceFqdn(), val)
		})
	case "to-fqdn":
		f.apply(func(f *flowpb.FlowFilter) {
			f.DestinationFqdn = append(f.GetDestinationFqdn(), val)
		})

	// pod filters
	case "pod":
		f.applyLeft(func(f *flowpb.FlowFilter) {
			f.SourcePod = append(f.GetSourcePod(), val)
		})
		f.applyRight(func(f *flowpb.FlowFilter) {
			f.DestinationPod = append(f.GetDestinationPod(), val)
		})
	case "from-pod":
		f.apply(func(f *flowpb.FlowFilter) {
			f.SourcePod = append(f.GetSourcePod(), val)
		})
	case "to-pod":
		f.apply(func(f *flowpb.FlowFilter) {
			f.DestinationPod = append(f.GetDestinationPod(), val)
		})
	// ip filters
	case "from-ip":
		f.apply(func(f *flowpb.FlowFilter) {
			f.SourceIp = append(f.GetSourceIp(), val)
		})
	case "snat-ip":
		f.apply(func(f *flowpb.FlowFilter) {
			f.SourceIpXlated = append(f.SourceIpXlated, val)
		})
	case "ip":
		f.applyLeft(func(f *flowpb.FlowFilter) {
			f.SourceIp = append(f.GetSourceIp(), val)
		})
		f.applyRight(func(f *flowpb.FlowFilter) {
			f.DestinationIp = append(f.GetDestinationIp(), val)
		})
	case "to-ip":
		f.apply(func(f *flowpb.FlowFilter) {
			f.DestinationIp = append(f.GetDestinationIp(), val)
		})
	// ip version filters
	case "ipv4":
		f.apply(func(f *flowpb.FlowFilter) {
			f.IpVersion = append(f.GetIpVersion(), flowpb.IPVersion_IPv4)
		})
	case "ipv6":
		f.apply(func(f *flowpb.FlowFilter) {
			f.IpVersion = append(f.GetIpVersion(), flowpb.IPVersion_IPv6)
		})
	case "ip-version":
		f.apply(func(f *flowpb.FlowFilter) {
			f.IpVersion = append(f.GetIpVersion(), ipVersion(val))
		})
	// label filters
	case "label":
		f.applyLeft(func(f *flowpb.FlowFilter) {
			f.SourceLabel = append(f.GetSourceLabel(), val)
		})
		f.applyRight(func(f *flowpb.FlowFilter) {
			f.DestinationLabel = append(f.GetDestinationLabel(), val)
		})
	case "from-label":
		f.apply(func(f *flowpb.FlowFilter) {
			f.SourceLabel = append(f.GetSourceLabel(), val)
		})
	case "to-label":
		f.apply(func(f *flowpb.FlowFilter) {
			f.DestinationLabel = append(f.GetDestinationLabel(), val)
		})

	// namespace filters (will be applied to pods and/or service filters)
	case "namespace":
		f.ns = append(f.ns, val)
	case "from-namespace":
		f.srcNs = append(f.srcNs, val)
	case "to-namespace":
		f.dstNs = append(f.dstNs, val)

	// namespace filters (will be applied to pods and/or service filters)
	case "all-namespaces":
		f.ns = append(f.ns, "")
	case "from-all-namespaces":
		f.srcNs = append(f.srcNs, "")
	case "to-all-namespaces":
		f.dstNs = append(f.dstNs, "")

	// service filters
	case "service":
		f.applyLeft(func(f *flowpb.FlowFilter) {
			f.SourceService = append(f.GetSourceService(), val)
		})
		f.applyRight(func(f *flowpb.FlowFilter) {
			f.DestinationService = append(f.GetDestinationService(), val)
		})
	case "from-service":
		f.apply(func(f *flowpb.FlowFilter) {
			f.SourceService = append(f.GetSourceService(), val)
		})
	case "to-service":
		f.apply(func(f *flowpb.FlowFilter) {
			f.DestinationService = append(f.GetDestinationService(), val)
		})

	// port filters
	case "port":
		f.applyLeft(func(f *flowpb.FlowFilter) {
			f.SourcePort = append(f.GetSourcePort(), val)
		})
		f.applyRight(func(f *flowpb.FlowFilter) {
			f.DestinationPort = append(f.GetDestinationPort(), val)
		})
	case "from-port":
		f.apply(func(f *flowpb.FlowFilter) {
			f.SourcePort = append(f.GetSourcePort(), val)
		})
	case "to-port":
		f.apply(func(f *flowpb.FlowFilter) {
			f.DestinationPort = append(f.GetDestinationPort(), val)
		})

	case "trace-id":
		f.apply(func(f *flowpb.FlowFilter) {
			f.TraceId = append(f.GetTraceId(), val)
		})

	case "verdict":
		if wipe {
			f.apply(func(f *flowpb.FlowFilter) {
				f.Verdict = nil
			})
		}

		vv, ok := flowpb.Verdict_value[val]
		if !ok {
			return fmt.Errorf("invalid --verdict value: %v", val)
		}
		f.apply(func(f *flowpb.FlowFilter) {
			f.Verdict = append(f.GetVerdict(), flowpb.Verdict(vv))
		})
	case "drop-reason-desc":
		if val == "" {
			return fmt.Errorf("empty --drop-reason-desc value")
		}
		v, ok := flowpb.DropReason_value[val]
		if !ok {
			return fmt.Errorf("invalid --drop-reason-desc value: %v", val)
		}
		f.apply(func(f *flowpb.FlowFilter) {
			f.DropReasonDesc = append(f.GetDropReasonDesc(), flowpb.DropReason(v))
		})

	case "http-status":
		f.apply(func(f *flowpb.FlowFilter) {
			f.HttpStatusCode = append(f.GetHttpStatusCode(), val)
		})

	case "http-method":
		f.apply(func(f *flowpb.FlowFilter) {
			f.HttpMethod = append(f.GetHttpMethod(), val)
		})

	case "http-path":
		f.apply(func(f *flowpb.FlowFilter) {
			f.HttpPath = append(f.GetHttpPath(), val)
		})
	case "http-url":
		f.apply(func(f *flowpb.FlowFilter) {
			f.HttpUrl = append(f.GetHttpUrl(), val)
		})

	case "http-header":
		key, hVal, found := strings.Cut(val, ":")
		if !found {
			return fmt.Errorf("invalid http-header value %q, expected name:value", val)
		}
		f.apply(func(f *flowpb.FlowFilter) {
			header := &flowpb.HTTPHeader{Key: key, Value: hVal}
			f.HttpHeader = append(f.GetHttpHeader(), header)
		})

	case "type":
		if wipe {
			f.apply(func(f *flowpb.FlowFilter) {
				f.EventType = nil
			})
		}

		typeFilter := &flowpb.EventTypeFilter{}

		s := strings.SplitN(val, ":", 2)
		t, ok := monitorAPI.MessageTypeNames[s[0]]
		if ok {
			typeFilter.Type = int32(t)
		} else {
			t, err := strconv.ParseUint(s[0], 10, 32)
			if err != nil {
				return fmt.Errorf("unable to parse type '%s', not a known type name and unable to parse as numeric value: %w", s[0], err)
			}
			typeFilter.Type = int32(t)
		}

		if len(s) > 1 {
			switch t {
			case monitorAPI.MessageTypeTrace:
				for k, v := range monitorAPI.TraceObservationPoints {
					if s[1] == v {
						typeFilter.MatchSubType = true
						typeFilter.SubType = int32(k)
						break
					}
				}
			case monitorAPI.MessageTypeAgent:
				// See agentEventSubtypes godoc for why we're
				// not using monitorAPI.AgentNotifications here.
				if st, ok := agentEventSubtypes[s[1]]; ok {
					typeFilter.MatchSubType = true
					typeFilter.SubType = int32(st)
				}
			}
			if !typeFilter.GetMatchSubType() {
				t, err := strconv.ParseUint(s[1], 10, 32)
				if err != nil {
					return fmt.Errorf("unable to parse event sub-type '%s', not a known sub-type name and unable to parse as numeric value: %w", s[1], err)
				}
				typeFilter.MatchSubType = true
				typeFilter.SubType = int32(t)
			}
		}
		f.apply(func(f *flowpb.FlowFilter) {
			f.EventType = append(f.GetEventType(), typeFilter)
		})
	case "protocol":
		f.apply(func(f *flowpb.FlowFilter) {
			f.Protocol = append(f.GetProtocol(), val)
		})

	// workload filters
	case "workload":
		workload := parseWorkload(val)
		f.applyLeft(func(f *flowpb.FlowFilter) {
			f.SourceWorkload = append(f.GetSourceWorkload(), workload)
		})
		f.applyRight(func(f *flowpb.FlowFilter) {
			f.DestinationWorkload = append(f.GetDestinationWorkload(), workload)
		})
	case "from-workload":
		workload := parseWorkload(val)
		f.apply(func(f *flowpb.FlowFilter) {
			f.SourceWorkload = append(f.GetSourceWorkload(), workload)
		})
	case "to-workload":
		workload := parseWorkload(val)
		f.apply(func(f *flowpb.FlowFilter) {
			f.DestinationWorkload = append(f.GetDestinationWorkload(), workload)
		})

	// identity filters
	case "identity":
		identity, err := parseIdentity(val)
		if err != nil {
			return fmt.Errorf("invalid security identity, expected one of %v or a numeric value", reservedIdentitiesNames())
		}
		f.applyLeft(func(f *flowpb.FlowFilter) {
			f.SourceIdentity = append(f.GetSourceIdentity(), identity.Uint32())
		})
		f.applyRight(func(f *flowpb.FlowFilter) {
			f.DestinationIdentity = append(f.GetDestinationIdentity(), identity.Uint32())
		})
	case "from-identity":
		identity, err := parseIdentity(val)
		if err != nil {
			return fmt.Errorf("invalid security identity, expected one of %v or a numeric value", reservedIdentitiesNames())
		}
		f.apply(func(f *flowpb.FlowFilter) {
			f.SourceIdentity = append(f.GetSourceIdentity(), identity.Uint32())
		})
	case "to-identity":
		identity, err := parseIdentity(val)
		if err != nil {
			return fmt.Errorf("invalid security identity, expected one of %v or a numeric value", reservedIdentitiesNames())
		}
		f.apply(func(f *flowpb.FlowFilter) {
			f.DestinationIdentity = append(f.GetDestinationIdentity(), identity.Uint32())
		})

	// node related filters
	case "node-name":
		f.apply(func(f *flowpb.FlowFilter) {
			f.NodeName = append(f.GetNodeName(), val)
		})
	case "node-label":
		f.apply(func(f *flowpb.FlowFilter) {
			f.NodeLabels = append(f.GetNodeLabels(), val)
		})

		// cluster Name filters
	case "cluster":
		f.apply(func(f *flowpb.FlowFilter) {
			f.NodeName = append(f.GetNodeName(), val+"/")
		})

	// TCP Flags filter
	case "tcp-flags":
		flags, err := parseTCPFlags(val)
		if err != nil {
			return err
		}
		f.apply(func(f *flowpb.FlowFilter) {
			f.TcpFlags = append(f.GetTcpFlags(), flags)
		})

	// traffic direction filter
	case "traffic-direction":
		switch td := strings.ToLower(val); td {
		case "ingress":
			f.apply(func(f *flowpb.FlowFilter) {
				f.TrafficDirection = append(f.GetTrafficDirection(), flowpb.TrafficDirection_INGRESS)
			})
		case "egress":
			f.apply(func(f *flowpb.FlowFilter) {
				f.TrafficDirection = append(f.GetTrafficDirection(), flowpb.TrafficDirection_EGRESS)
			})
		default:
			return fmt.Errorf("%s: invalid traffic direction, expected ingress or egress", td)
		}
	case "cel-expression":
		f.apply(func(f *flowpb.FlowFilter) {
			if f.GetExperimental() == nil {
				f.Experimental = &flowpb.FlowFilter_Experimental{}
			}
			f.Experimental.CelExpression = append(f.Experimental.CelExpression, val)
		})
	case "interface":
		f.apply(func(f *flowpb.FlowFilter) {
			f.Interface = append(f.Interface, &flowpb.NetworkInterface{Name: val})
		})
	}

	if err := f.checkNamespaceConflicts(f.left); err != nil {
		return err
	}
	return f.checkNamespaceConflicts(f.right)
}

func (of flowFilter) Type() string {
	return "filter"
}

// Small dispatcher on top of a filter that allows all the filter arguments to
// flow through the same object. By default, Cobra doesn't call `Set()` with the
// name of the argument, only it's value.
type filterDispatch struct {
	*flowFilter

	name string
	def  []string
}

func (d filterDispatch) Set(s string) error {
	return d.flowFilter.Set(d.name, s, true)
}

// for some reason String() is used for default value in pflag/cobra
func (d filterDispatch) String() string {
	if len(d.def) == 0 {
		return ""
	}

	var b bytes.Buffer
	first := true
	b.WriteString("[")
	for _, def := range d.def {
		if first {
			first = false
		} else {
			// if not first, write a comma
			b.WriteString(",")
		}
		b.WriteString(def)
	}
	b.WriteString("]")

	return b.String()
}

func filterVar(
	name string,
	of *flowFilter,
	desc string,
) (pflag.Value, flagName, flagDesc) {
	return &filterDispatch{
		name:       name,
		flowFilter: of,
	}, name, desc
}

func filterVarP(
	name string,
	short string,
	of *flowFilter,
	def []string,
	desc string,
) (pflag.Value, flagName, shortName, flagDesc) {
	d := &filterDispatch{
		name:       name,
		def:        def,
		flowFilter: of,
	}
	for _, val := range def {
		d.flowFilter.Set(name, val, false /* do not track */)

	}
	return d, name, short, desc
}
