// Copyright 2019-2020 Authors of Hubble
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

package filters

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	ciliumLabels "github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/monitor/api"
	k8sLabels "k8s.io/apimachinery/pkg/labels"

	pb "github.com/cilium/hubble/api/v1/flow"
	v1 "github.com/cilium/hubble/pkg/api/v1"
	"github.com/cilium/hubble/pkg/k8s"
)

// FilterFunc is the function will be used to filter the given data.
// Should return true if the filter is hit, false otherwise.
type FilterFunc func(ev *v1.Event) bool

// FilterFuncs is a combination of multiple filters, typically applied together.
type FilterFuncs []FilterFunc

// Apply filters the flow with the given white- and blacklist. Returns true
// if the flow should be included in the result.
func Apply(whitelist, blacklist FilterFuncs, ev *v1.Event) bool {
	return whitelist.MatchOne(ev) && blacklist.MatchNone(ev)
}

// MatchAll returns true if all the filters match the provided data, i.e. AND.
func (fs FilterFuncs) MatchAll(ev *v1.Event) bool {
	for _, f := range fs {
		if !f(ev) {
			return false
		}
	}
	return true
}

// MatchOne returns true if at least one of the filters match the provided data or
// if no filters are specified, i.e. OR.
func (fs FilterFuncs) MatchOne(ev *v1.Event) bool {
	if len(fs) == 0 {
		return true
	}

	for _, f := range fs {
		if f(ev) {
			return true
		}
	}
	return false
}

// MatchNone returns true if none of the filters match the provided data or
// if no filters are specified, i.e. NOR
func (fs FilterFuncs) MatchNone(ev *v1.Event) bool {
	if len(fs) == 0 {
		return true
	}

	for _, f := range fs {
		if f(ev) {
			return false
		}
	}
	return true
}

func sourceIP(ev *v1.Event) string {
	return ev.GetFlow().GetIP().GetSource()
}

func destinationIP(ev *v1.Event) string {
	return ev.GetFlow().GetIP().GetDestination()
}

func filterByIPs(ips []string, getIP func(*v1.Event) string) (FilterFunc, error) {
	for _, ip := range ips {
		if net.ParseIP(ip) == nil {
			return nil, fmt.Errorf("invalid IP address in filter: %q", ip)
		}
	}

	return func(ev *v1.Event) bool {
		eventIP := getIP(ev)
		if eventIP == "" {
			return false
		}

		for _, ip := range ips {
			if ip == eventIP {
				return true
			}
		}

		return false
	}, nil
}

func sourcePod(ev *v1.Event) (ns, pod string) {
	ep := ev.GetFlow().GetSource()
	return ep.GetNamespace(), ep.GetPodName()
}

func destinationPod(ev *v1.Event) (ns, pod string) {
	ep := ev.GetFlow().GetDestination()
	return ep.GetNamespace(), ep.GetPodName()
}

func sourceService(ev *v1.Event) (ns, svc string) {
	s := ev.GetFlow().GetSourceService()
	return s.GetNamespace(), s.GetName()
}

func destinationService(ev *v1.Event) (ns, svc string) {
	s := ev.GetFlow().GetDestinationService()
	return s.GetNamespace(), s.GetName()
}

func filterByNamespacedName(names []string, getName func(*v1.Event) (ns, name string)) (FilterFunc, error) {
	type nameFilter struct{ ns, prefix string }
	nameFilters := make([]nameFilter, 0, len(names))
	for _, name := range names {
		ns, prefix := k8s.ParseNamespaceName(name)
		if ns == "" && prefix == "" {
			return nil, fmt.Errorf("invalid filter, must be [namespace/][<name>], got %q", name)
		}
		nameFilters = append(nameFilters, nameFilter{ns, prefix})
	}

	return func(ev *v1.Event) bool {
		eventNs, eventName := getName(ev)
		if eventNs == "" && eventName == "" {
			return false
		}

		for _, f := range nameFilters {
			if (f.prefix == "" || strings.HasPrefix(eventName, f.prefix)) && f.ns == eventNs {
				return true
			}
		}

		return false
	}, nil
}

func sourceFQDN(ev *v1.Event) []string {
	return ev.GetFlow().GetSourceNames()
}

func destinationFQDN(ev *v1.Event) []string {
	return ev.GetFlow().GetDestinationNames()
}

var (
	fqdnFilterAllowedChars  = "[-a-zA-Z0-9_.]*"
	fqdnFilterIsValidFilter = regexp.MustCompile("^[-a-zA-Z0-9_.*]+$")
)

func parseFQDNFilter(pattern string) (*regexp.Regexp, error) {
	pattern = strings.ToLower(pattern)
	pattern = strings.TrimSpace(pattern)
	pattern = strings.TrimSuffix(pattern, ".")

	if !fqdnFilterIsValidFilter.MatchString(pattern) {
		return nil, fmt.Errorf(`only alphanumeric ASCII characters, the hyphen "-", "." and "*" are allowed: %s`,
			pattern)
	}

	// "." becomes a literal .
	pattern = strings.Replace(pattern, ".", "[.]", -1)

	// "*" becomes a zero or more of the allowed characters
	pattern = strings.Replace(pattern, "*", fqdnFilterAllowedChars, -1)

	return regexp.Compile("^" + pattern + "$")
}

func filterByFQDNs(fqdnPatterns []string, getFQDNs func(*v1.Event) []string) (FilterFunc, error) {
	matchPatterns := make([]*regexp.Regexp, 0, len(fqdnPatterns))
	for _, pattern := range fqdnPatterns {
		re, err := parseFQDNFilter(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid FQDN in filter: %s", err)
		}
		matchPatterns = append(matchPatterns, re)
	}

	return func(ev *v1.Event) bool {
		names := getFQDNs(ev)
		if len(names) == 0 {
			return false
		}

		for _, name := range names {
			for _, re := range matchPatterns {
				if re.MatchString(name) {
					return true
				}
			}
		}

		return false
	}, nil
}

func sourceLabels(ev *v1.Event) k8sLabels.Labels {
	labels := ev.GetFlow().GetSource().GetLabels()
	return ciliumLabels.ParseLabelArrayFromArray(labels)
}

func destinationLabels(ev *v1.Event) k8sLabels.Labels {
	labels := ev.GetFlow().GetDestination().GetLabels()
	return ciliumLabels.ParseLabelArrayFromArray(labels)
}

var (
	labelSelectorWithColon = regexp.MustCompile(`([^,]\s*[a-z0-9-]+):([a-z0-9-]+)`)
)

func parseSelector(selector string) (k8sLabels.Selector, error) {
	// ciliumLabels.LabelArray extends the k8sLabels.Selector logic with
	// support for Cilium source prefixes such as "k8s:foo" or "any:bar".
	// It does this by treating the string before the first dot as the source
	// prefix, i.e. `k8s.foo` is treated like `k8s:foo`. This translation is
	// needed because k8sLabels.Selector does not support colons in label names.
	//
	// We do not want to expose this implementation detail to the user,
	// therefore we translate any user-specified source prefixes by
	// replacing colon-based source prefixes in labels with dot-based prefixes,
	// i.e. "k8s:foo in (bar, baz)" becomes "k8s.foo in (bar, baz)".

	translated := labelSelectorWithColon.ReplaceAllString(selector, "${1}.${2}")
	return k8sLabels.Parse(translated)
}

func filterByLabelSelectors(labelSelectors []string, getLabels func(*v1.Event) k8sLabels.Labels) (FilterFunc, error) {
	selectors := make([]k8sLabels.Selector, 0, len(labelSelectors))
	for _, selector := range labelSelectors {
		s, err := parseSelector(selector)
		if err != nil {
			return nil, err
		}
		selectors = append(selectors, s)
	}

	return func(ev *v1.Event) bool {
		labels := getLabels(ev)
		for _, selector := range selectors {
			if selector.Matches(labels) {
				return true
			}
		}
		return false
	}, nil
}

func filterByVerdicts(vs []pb.Verdict) FilterFunc {
	return func(ev *v1.Event) bool {
		flow := ev.GetFlow()
		if flow == nil {
			return false
		}
		for _, verdict := range vs {
			if verdict == flow.GetVerdict() {
				return true
			}
		}

		return false
	}
}

func filterByEventType(types []*pb.EventTypeFilter) FilterFunc {
	return func(ev *v1.Event) bool {
		event := ev.GetFlow().GetEventType()
		if event == nil {
			return false
		}

		for _, typeFilter := range types {
			if t := typeFilter.GetType(); t != 0 && event.Type != t {
				continue
			}

			if typeFilter.GetMatchSubType() && typeFilter.GetSubType() != event.SubType {
				continue
			}

			return true
		}

		return false
	}
}

func httpMatchCompatibleEventFilter(types []*pb.EventTypeFilter) bool {
	if len(types) == 0 {
		return true
	}

	for _, t := range types {
		if t.GetType() == api.MessageTypeAccessLog {
			return true
		}
	}

	return false
}

var (
	httpStatusCodeFull   = regexp.MustCompile(`[1-5][0-9]{2}`)
	httpStatusCodePrefix = regexp.MustCompile(`^([1-5][0-9]?\+)$`)
)

func filterByHTTPStatusCode(statusCodePrefixes []string) (FilterFunc, error) {
	var full, prefix []string
	for _, s := range statusCodePrefixes {
		switch {
		case httpStatusCodeFull.MatchString(s):
			full = append(full, s)
		case httpStatusCodePrefix.MatchString(s):
			prefix = append(prefix, strings.TrimSuffix(s, "+"))
		default:
			return nil, fmt.Errorf("invalid status code prefix: %q", s)
		}
	}

	return func(ev *v1.Event) bool {
		http := ev.GetFlow().GetL7().GetHttp()
		// Not an HTTP response record
		if http == nil || http.Code == 0 {
			return false
		}

		// Check for both full matches or prefix matches
		httpStatusCode := fmt.Sprintf("%03d", http.Code)
		for _, f := range full {
			if httpStatusCode == f {
				return true
			}
		}
		for _, p := range prefix {
			if strings.HasPrefix(httpStatusCode, p) {
				return true
			}
		}

		return false
	}, nil
}

func filterByProtocol(protocols []string) (FilterFunc, error) {
	var l4Protocols, l7Protocols []string
	for _, p := range protocols {
		proto := strings.ToLower(p)
		switch proto {
		case "icmp", "icmpv4", "icmpv6", "tcp", "udp":
			l4Protocols = append(l4Protocols, proto)
		case "dns", "http", "kafka":
			l7Protocols = append(l7Protocols, proto)
		default:
			return nil, fmt.Errorf("unkown protocol: %q", p)
		}
	}

	return func(ev *v1.Event) bool {
		l4 := ev.GetFlow().GetL4()
		for _, proto := range l4Protocols {
			switch proto {
			case "icmp":
				if l4.GetICMPv4() != nil || l4.GetICMPv6() != nil {
					return true
				}
			case "icmpv4":
				if l4.GetICMPv4() != nil {
					return true
				}
			case "icmpv6":
				if l4.GetICMPv6() != nil {
					return true
				}
			case "tcp":
				if l4.GetTCP() != nil {
					return true
				}
			case "udp":
				if l4.GetUDP() != nil {
					return true
				}
			}
		}

		l7 := ev.GetFlow().GetL7()
		for _, proto := range l7Protocols {
			switch proto {
			case "dns":
				if l7.GetDns() != nil {
					return true
				}
			case "http":
				if l7.GetHttp() != nil {
					return true
				}
			case "kafka":
				if l7.GetKafka() != nil {
					return true
				}
			}
		}

		return false
	}, nil
}

func sourcePort(ev *v1.Event) (port uint16, ok bool) {
	l4 := ev.GetFlow().GetL4()
	if tcp := l4.GetTCP(); tcp != nil {
		return uint16(tcp.SourcePort), true
	}
	if udp := l4.GetUDP(); udp != nil {
		return uint16(udp.SourcePort), true
	}
	return 0, false
}

func destinationPort(ev *v1.Event) (port uint16, ok bool) {
	l4 := ev.GetFlow().GetL4()
	if tcp := l4.GetTCP(); tcp != nil {
		return uint16(tcp.DestinationPort), true
	}
	if udp := l4.GetUDP(); udp != nil {
		return uint16(udp.DestinationPort), true
	}
	return 0, false
}

func filterByPort(portStrs []string, getPort func(*v1.Event) (port uint16, ok bool)) (FilterFunc, error) {
	ports := make([]uint16, 0, len(portStrs))
	for _, p := range portStrs {
		port, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %s", p, err)
		}
		ports = append(ports, uint16(port))
	}

	return func(ev *v1.Event) bool {
		if port, ok := getPort(ev); ok {
			for _, p := range ports {
				if p == port {
					return true
				}
			}
		}
		return false
	}, nil
}

func filterByReplyField(replyParams []bool) FilterFunc {
	return func(ev *v1.Event) bool {
		if len(replyParams) == 0 {
			return true
		}
		switch ev.Event.(type) {
		case v1.Flow:
			reply := ev.GetFlow().GetReply()
			for _, replyParam := range replyParams {
				if reply == replyParam {
					return true
				}
			}
		}
		return false
	}
}

// filterByDNSQueries returns a FilterFunc that filters a flow by L7.DNS.query field.
// The filter function returns true if and only if the DNS query field matches any of
// the regular expressions.
func filterByDNSQueries(queryPatterns []string) (FilterFunc, error) {
	var queries []*regexp.Regexp
	for _, pattern := range queryPatterns {
		query, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to compile regexp: %v", err)
		}
		queries = append(queries, query)
	}
	return func(ev *v1.Event) bool {
		dns := ev.GetFlow().GetL7().GetDns()
		if dns == nil {
			return false
		}
		for _, query := range queries {
			if query.MatchString(dns.Query) {
				return true
			}
		}
		return false
	}, nil
}

// BuildFilter builds a filter based on a FlowFilter. It returns:
// - the FilterFunc to be used to filter packets based on the requested
//   FlowFilter;
// - an error in case something went wrong.
func BuildFilter(ff *pb.FlowFilter) (FilterFuncs, error) {
	var fs []FilterFunc

	// Always prioritize the type filter first. If used it will save a lot of
	// decoding time.
	types := ff.GetEventType()
	if len(types) > 0 {
		fs = append(fs, filterByEventType(types))
	}

	if ff.GetSourceIp() != nil {
		ipf, err := filterByIPs(ff.GetSourceIp(), sourceIP)
		if err != nil {
			return nil, err
		}
		fs = append(fs, ipf)
	}

	if ff.GetDestinationIp() != nil {
		ipf, err := filterByIPs(ff.GetDestinationIp(), destinationIP)
		if err != nil {
			return nil, err
		}
		fs = append(fs, ipf)
	}

	if ff.GetSourcePod() != nil {
		pf, err := filterByNamespacedName(ff.GetSourcePod(), sourcePod)
		if err != nil {
			return nil, err
		}
		fs = append(fs, pf)
	}

	if ff.GetDestinationPod() != nil {
		pf, err := filterByNamespacedName(ff.GetDestinationPod(), destinationPod)
		if err != nil {
			return nil, err
		}
		fs = append(fs, pf)
	}

	if ff.GetSourceFqdn() != nil {
		ff, err := filterByFQDNs(ff.GetSourceFqdn(), sourceFQDN)
		if err != nil {
			return nil, err
		}
		fs = append(fs, ff)
	}

	if ff.GetDestinationFqdn() != nil {
		ff, err := filterByFQDNs(ff.GetDestinationFqdn(), destinationFQDN)
		if err != nil {
			return nil, err
		}
		fs = append(fs, ff)
	}

	if ff.GetVerdict() != nil {
		fs = append(fs, filterByVerdicts(ff.GetVerdict()))
	}

	if ff.GetHttpStatusCode() != nil {
		if !httpMatchCompatibleEventFilter(types) {
			return nil, errors.New("filtering by http status code requires " +
				"the event type filter to only match 'l7' events")
		}

		hsf, err := filterByHTTPStatusCode(ff.GetHttpStatusCode())
		if err != nil {
			return nil, fmt.Errorf("invalid http status code filter: %v", err)
		}
		fs = append(fs, hsf)
	}

	if ff.GetSourceLabel() != nil {
		slf, err := filterByLabelSelectors(ff.GetSourceLabel(), sourceLabels)
		if err != nil {
			return nil, fmt.Errorf("invalid source label filter: %v", err)
		}
		fs = append(fs, slf)
	}

	if ff.GetDestinationLabel() != nil {
		dlf, err := filterByLabelSelectors(ff.GetDestinationLabel(), destinationLabels)
		if err != nil {
			return nil, fmt.Errorf("invalid destination label filter: %v", err)
		}
		fs = append(fs, dlf)
	}

	if ff.GetSourceService() != nil {
		ssf, err := filterByNamespacedName(ff.GetSourceService(), sourceService)
		if err != nil {
			return nil, fmt.Errorf("invalid source service filter: %v", err)
		}
		fs = append(fs, ssf)
	}

	if ff.GetDestinationService() != nil {
		dsf, err := filterByNamespacedName(ff.GetDestinationService(), destinationService)
		if err != nil {
			return nil, fmt.Errorf("invalid destination service filter: %v", err)
		}
		fs = append(fs, dsf)
	}

	if ff.GetProtocol() != nil {
		pf, err := filterByProtocol(ff.GetProtocol())
		if err != nil {
			return nil, fmt.Errorf("invalid protocol filter: %v", err)
		}
		fs = append(fs, pf)
	}

	if ff.GetSourcePort() != nil {
		spf, err := filterByPort(ff.GetSourcePort(), sourcePort)
		if err != nil {
			return nil, fmt.Errorf("invalid source port filter: %v", err)
		}
		fs = append(fs, spf)
	}

	if ff.GetDestinationPort() != nil {
		dpf, err := filterByPort(ff.GetDestinationPort(), destinationPort)
		if err != nil {
			return nil, fmt.Errorf("invalid destination port filter: %v", err)
		}
		fs = append(fs, dpf)
	}

	if ff.GetReply() != nil {
		fs = append(fs, filterByReplyField(ff.GetReply()))
	}

	if ff.GetDnsQuery() != nil {
		dnsFilters, err := filterByDNSQueries(ff.GetDnsQuery())
		if err != nil {
			return nil, fmt.Errorf("invalid DNS query filter: %v", err)
		}
		fs = append(fs, dnsFilters)
	}

	return fs, nil
}

// BuildFilterList constructs a list of filter functions representing the list
// of FlowFilter. It returns:
// - the FilterFunc to be used to filter packets based on the requested
//   FlowFilter;
// - an error in case something went wrong.
func BuildFilterList(ff []*pb.FlowFilter) (FilterFuncs, error) {
	filterList := make([]FilterFunc, 0, len(ff))

	for _, flowFilter := range ff {
		// Build filter matching on all requirements of the FlowFilter
		tf, err := BuildFilter(flowFilter)
		if err != nil {
			return nil, err
		}

		// All filters representing a FlowFilter must match
		filterFunc := func(ev *v1.Event) bool {
			return tf.MatchAll(ev)
		}

		filterList = append(filterList, filterFunc)
	}

	return filterList, nil
}
