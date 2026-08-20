// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package qos

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/policy/api"
)

func mechanism(name string, typ v2alpha1.QoSMechanismType) *v2alpha1.CiliumQoSMechanism {
	return &v2alpha1.CiliumQoSMechanism{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       v2alpha1.CiliumQoSMechanismSpec{Type: typ},
	}
}

func dscpClass(name, mechanismName string, priority int32, value uint8) *v2alpha1.CiliumQoSClass {
	return &v2alpha1.CiliumQoSClass{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v2alpha1.CiliumQoSClassSpec{
			Priority:     priority,
			MechanismRef: v2alpha1.QoSMechanismReference{Name: mechanismName},
			Parameters: v2alpha1.QoSClassParameters{
				DSCP: &v2alpha1.DSCPParameters{Value: value},
			},
		},
	}
}

func nodePriorityClass(name, mechanismName string, priority int32, level v2alpha1.NodePriorityLevel) *v2alpha1.CiliumQoSClass {
	return &v2alpha1.CiliumQoSClass{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v2alpha1.CiliumQoSClassSpec{
			Priority:     priority,
			MechanismRef: v2alpha1.QoSMechanismReference{Name: mechanismName},
			Parameters: v2alpha1.QoSClassParameters{
				NodePriority: &v2alpha1.NodePriorityParameters{Priority: level},
			},
		},
	}
}

func prefixes(cidrs ...string) []iputil.Prefix {
	out := make([]iputil.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		out = append(out, iputil.PrefixFrom(netip.MustParsePrefix(cidr)))
	}
	return out
}

func ports(entries ...v2alpha1.QoSPortProtocol) []v2alpha1.QoSPortRule {
	return []v2alpha1.QoSPortRule{{Ports: entries}}
}

func classRefs(names ...string) []v2alpha1.QoSClassReference {
	out := make([]v2alpha1.QoSClassReference, 0, len(names))
	for _, name := range names {
		out = append(out, v2alpha1.QoSClassReference{Name: name})
	}
	return out
}

func policy(namespace, name string, egress ...v2alpha1.QoSEgressRule) *v2alpha1.CiliumQoSPolicy {
	return &v2alpha1.CiliumQoSPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: v2alpha1.CiliumQoSPolicySpec{
			PodSelector: &slimv1.LabelSelector{},
			Egress:      egress,
		},
	}
}

// mechanisms and classes shared by the table tests: the "voice" and
// "guaranteed" classes of the QoS API proposal, plus a "bulk" class that
// competes with "voice" for the DSCP mechanism.
func testClasses(t *testing.T) map[string]Class {
	t.Helper()

	mechanisms := map[string]*v2alpha1.CiliumQoSMechanism{
		"dscp":          mechanism("dscp", v2alpha1.QoSMechanismDSCP),
		"node-priority": mechanism("node-priority", v2alpha1.QoSMechanismNodePriority),
	}

	classes := make(map[string]Class)
	for _, class := range []*v2alpha1.CiliumQoSClass{
		dscpClass("voice", "dscp", 100, 46),
		dscpClass("bulk", "dscp", 10, 8),
		dscpClass("tied-with-voice", "dscp", 100, 34),
		nodePriorityClass("guaranteed", "node-priority", 90, v2alpha1.NodePriorityGuaranteed),
	} {
		resolved, err := ResolveClass(class, mechanisms)
		require.NoError(t, err)
		classes[resolved.Name] = resolved
	}

	return classes
}

func TestResolveClass(t *testing.T) {
	mechanisms := map[string]*v2alpha1.CiliumQoSMechanism{
		"dscp":          mechanism("dscp", v2alpha1.QoSMechanismDSCP),
		"node-priority": mechanism("node-priority", v2alpha1.QoSMechanismNodePriority),
		"future":        mechanism("future", v2alpha1.QoSMechanismType("SomethingElse")),
	}

	t.Run("dscp", func(t *testing.T) {
		resolved, err := ResolveClass(dscpClass("voice", "dscp", 100, 46), mechanisms)
		require.NoError(t, err)
		assert.Equal(t, Class{
			Name:      "voice",
			Mechanism: v2alpha1.QoSMechanismDSCP,
			Priority:  100,
			DSCP:      46,
		}, resolved)
	})

	t.Run("node priority", func(t *testing.T) {
		resolved, err := ResolveClass(nodePriorityClass("guaranteed", "node-priority", 90, v2alpha1.NodePriorityGuaranteed), mechanisms)
		require.NoError(t, err)
		assert.Equal(t, Class{
			Name:         "guaranteed",
			Mechanism:    v2alpha1.QoSMechanismNodePriority,
			Priority:     90,
			NodePriority: v2alpha1.NodePriorityGuaranteed,
		}, resolved)
	})

	t.Run("undeclared mechanism", func(t *testing.T) {
		_, err := ResolveClass(dscpClass("voice", "missing", 100, 46), mechanisms)
		assert.ErrorContains(t, err, `undeclared mechanism "missing"`)
	})

	t.Run("parameters do not match the mechanism", func(t *testing.T) {
		_, err := ResolveClass(dscpClass("voice", "node-priority", 100, 46), mechanisms)
		assert.ErrorContains(t, err, "does not set parameters.nodePriority")
	})

	t.Run("unknown mechanism type", func(t *testing.T) {
		_, err := ResolveClass(dscpClass("voice", "future", 100, 46), mechanisms)
		assert.ErrorContains(t, err, "unknown type")
	})
}

func TestTableLookup(t *testing.T) {
	classes := testClasses(t)

	dscp := func(value uint8) *uint8 { return &value }
	nodePrio := func(level v2alpha1.NodePriorityLevel) *v2alpha1.NodePriorityLevel { return &level }

	tests := []struct {
		name     string
		policies []*v2alpha1.CiliumQoSPolicy
		flow     Flow
		want     Marking
	}{
		{
			name: "no rules leaves the flow unmarked",
			flow: Flow{Dst: netip.MustParseAddr("10.0.0.1"), Proto: api.ProtoTCP, DstPort: 80},
		},
		{
			name: "a rule without selectors matches every flow",
			policies: []*v2alpha1.CiliumQoSPolicy{
				policy("prod", "all", v2alpha1.QoSEgressRule{QoSClassRefs: classRefs("voice")}),
			},
			flow: Flow{Dst: netip.MustParseAddr("10.0.0.1"), Proto: api.ProtoTCP, DstPort: 80},
			want: Marking{DSCP: dscp(46)},
		},
		{
			name: "classes of different mechanisms are both applied",
			policies: []*v2alpha1.CiliumQoSPolicy{
				policy("prod", "both", v2alpha1.QoSEgressRule{
					ToCIDR:       prefixes("192.168.1.0/24"),
					ToPorts:      ports(v2alpha1.QoSPortProtocol{Port: "5060", Protocol: api.ProtoUDP}),
					QoSClassRefs: classRefs("voice", "guaranteed"),
				}),
			},
			flow: Flow{Dst: netip.MustParseAddr("192.168.1.5"), Proto: api.ProtoUDP, DstPort: 5060},
			want: Marking{DSCP: dscp(46), NodePriority: nodePrio(v2alpha1.NodePriorityGuaranteed)},
		},
		{
			name: "a destination outside the CIDR does not match",
			policies: []*v2alpha1.CiliumQoSPolicy{
				policy("prod", "cidr", v2alpha1.QoSEgressRule{
					ToCIDR:       prefixes("192.168.1.0/24"),
					QoSClassRefs: classRefs("voice"),
				}),
			},
			flow: Flow{Dst: netip.MustParseAddr("10.0.0.1"), Proto: api.ProtoTCP, DstPort: 80},
		},
		{
			name: "an L4 rule wins over a broader L3 rule",
			policies: []*v2alpha1.CiliumQoSPolicy{
				policy("prod", "l3", v2alpha1.QoSEgressRule{
					ToCIDR:       prefixes("192.168.1.0/24"),
					QoSClassRefs: classRefs("bulk"),
				}),
				policy("prod", "l4", v2alpha1.QoSEgressRule{
					ToPorts:      ports(v2alpha1.QoSPortProtocol{Port: "5060", Protocol: api.ProtoUDP}),
					QoSClassRefs: classRefs("voice"),
				}),
			},
			flow: Flow{Dst: netip.MustParseAddr("192.168.1.5"), Proto: api.ProtoUDP, DstPort: 5060},
			want: Marking{DSCP: dscp(46)},
		},
		{
			name: "a longer prefix wins over a shorter one",
			policies: []*v2alpha1.CiliumQoSPolicy{
				policy("prod", "wide", v2alpha1.QoSEgressRule{
					ToCIDR:       prefixes("192.168.0.0/16"),
					QoSClassRefs: classRefs("voice"),
				}),
				policy("prod", "narrow", v2alpha1.QoSEgressRule{
					ToCIDR:       prefixes("192.168.1.0/24"),
					QoSClassRefs: classRefs("bulk"),
				}),
			},
			flow: Flow{Dst: netip.MustParseAddr("192.168.1.5"), Proto: api.ProtoTCP, DstPort: 80},
			want: Marking{DSCP: dscp(8)},
		},
		{
			name: "an unconstrained rule loses to any CIDR match",
			policies: []*v2alpha1.CiliumQoSPolicy{
				policy("prod", "any", v2alpha1.QoSEgressRule{
					QoSClassRefs: classRefs("voice"),
				}),
				policy("prod", "default-route", v2alpha1.QoSEgressRule{
					ToCIDR:       prefixes("0.0.0.0/0"),
					QoSClassRefs: classRefs("bulk"),
				}),
			},
			flow: Flow{Dst: netip.MustParseAddr("192.168.1.5"), Proto: api.ProtoTCP, DstPort: 80},
			want: Marking{DSCP: dscp(8)},
		},
		{
			name: "class priority breaks ties between equally specific rules",
			policies: []*v2alpha1.CiliumQoSPolicy{
				policy("prod", "a", v2alpha1.QoSEgressRule{
					ToCIDR:       prefixes("192.168.1.0/24"),
					QoSClassRefs: classRefs("bulk"),
				}),
				policy("prod", "b", v2alpha1.QoSEgressRule{
					ToCIDR:       prefixes("192.168.1.0/24"),
					QoSClassRefs: classRefs("voice"),
				}),
			},
			flow: Flow{Dst: netip.MustParseAddr("192.168.1.5"), Proto: api.ProtoTCP, DstPort: 80},
			want: Marking{DSCP: dscp(46)},
		},
		{
			name: "an exact port wins over a range",
			policies: []*v2alpha1.CiliumQoSPolicy{
				policy("prod", "range", v2alpha1.QoSEgressRule{
					ToPorts:      ports(v2alpha1.QoSPortProtocol{Port: "5000", EndPort: 6000, Protocol: api.ProtoUDP}),
					QoSClassRefs: classRefs("bulk"),
				}),
				policy("prod", "exact", v2alpha1.QoSEgressRule{
					ToPorts:      ports(v2alpha1.QoSPortProtocol{Port: "5060", Protocol: api.ProtoUDP}),
					QoSClassRefs: classRefs("voice"),
				}),
			},
			flow: Flow{Dst: netip.MustParseAddr("10.0.0.1"), Proto: api.ProtoUDP, DstPort: 5060},
			want: Marking{DSCP: dscp(46)},
		},
		{
			name: "a port outside the range does not match",
			policies: []*v2alpha1.CiliumQoSPolicy{
				policy("prod", "range", v2alpha1.QoSEgressRule{
					ToPorts:      ports(v2alpha1.QoSPortProtocol{Port: "5000", EndPort: 6000, Protocol: api.ProtoUDP}),
					QoSClassRefs: classRefs("voice"),
				}),
			},
			flow: Flow{Dst: netip.MustParseAddr("10.0.0.1"), Proto: api.ProtoUDP, DstPort: 6001},
		},
		{
			name: "an explicit protocol wins over a wildcard one",
			policies: []*v2alpha1.CiliumQoSPolicy{
				policy("prod", "any-proto", v2alpha1.QoSEgressRule{
					ToPorts:      ports(v2alpha1.QoSPortProtocol{Port: "8080"}),
					QoSClassRefs: classRefs("bulk"),
				}),
				policy("prod", "tcp", v2alpha1.QoSEgressRule{
					ToPorts:      ports(v2alpha1.QoSPortProtocol{Port: "8080", Protocol: api.ProtoTCP}),
					QoSClassRefs: classRefs("voice"),
				}),
			},
			flow: Flow{Dst: netip.MustParseAddr("10.0.0.1"), Proto: api.ProtoTCP, DstPort: 8080},
			want: Marking{DSCP: dscp(46)},
		},
		{
			name: "a wildcard protocol does not match protocols without ports",
			policies: []*v2alpha1.CiliumQoSPolicy{
				policy("prod", "any-proto", v2alpha1.QoSEgressRule{
					ToPorts:      ports(v2alpha1.QoSPortProtocol{Port: "0", Protocol: api.ProtoAny}),
					QoSClassRefs: classRefs("voice"),
				}),
			},
			flow: Flow{Dst: netip.MustParseAddr("10.0.0.1"), Proto: api.L4Proto("ICMP")},
		},
		{
			name: "the protocol has to match",
			policies: []*v2alpha1.CiliumQoSPolicy{
				policy("prod", "udp", v2alpha1.QoSEgressRule{
					ToPorts:      ports(v2alpha1.QoSPortProtocol{Port: "5060", Protocol: api.ProtoUDP}),
					QoSClassRefs: classRefs("voice"),
				}),
			},
			flow: Flow{Dst: netip.MustParseAddr("10.0.0.1"), Proto: api.ProtoTCP, DstPort: 5060},
		},
		{
			name: "source ports are matched too",
			policies: []*v2alpha1.CiliumQoSPolicy{
				policy("prod", "src", v2alpha1.QoSEgressRule{
					FromPorts:    ports(v2alpha1.QoSPortProtocol{Port: "9000", Protocol: api.ProtoTCP}),
					QoSClassRefs: classRefs("voice"),
				}),
			},
			flow: Flow{Dst: netip.MustParseAddr("10.0.0.1"), Proto: api.ProtoTCP, SrcPort: 9000, DstPort: 80},
			want: Marking{DSCP: dscp(46)},
		},
		{
			name: "a rule constraining both ends wins over one constraining the destination only",
			policies: []*v2alpha1.CiliumQoSPolicy{
				policy("prod", "dst-only", v2alpha1.QoSEgressRule{
					ToPorts:      ports(v2alpha1.QoSPortProtocol{Port: "80", Protocol: api.ProtoTCP}),
					QoSClassRefs: classRefs("voice"),
				}),
				policy("prod", "both-ends", v2alpha1.QoSEgressRule{
					ToPorts:      ports(v2alpha1.QoSPortProtocol{Port: "80", Protocol: api.ProtoTCP}),
					FromPorts:    ports(v2alpha1.QoSPortProtocol{Port: "9000", Protocol: api.ProtoTCP}),
					QoSClassRefs: classRefs("bulk"),
				}),
			},
			flow: Flow{Dst: netip.MustParseAddr("10.0.0.1"), Proto: api.ProtoTCP, SrcPort: 9000, DstPort: 80},
			want: Marking{DSCP: dscp(8)},
		},
		{
			name: "IPv6 destinations are matched",
			policies: []*v2alpha1.CiliumQoSPolicy{
				policy("prod", "v6", v2alpha1.QoSEgressRule{
					ToCIDR:       prefixes("2001:db8::/32"),
					QoSClassRefs: classRefs("voice"),
				}),
			},
			flow: Flow{Dst: netip.MustParseAddr("2001:db8::1"), Proto: api.ProtoTCP, DstPort: 80},
			want: Marking{DSCP: dscp(46)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			table, errs := NewTable(tt.policies, classes)
			require.Empty(t, errs)
			assert.Equal(t, tt.want, table.Lookup(tt.flow))
		})
	}
}

// TestTableLookupIsOrderIndependent checks that two classes that tie on both
// specificity and priority resolve to the same class regardless of the order
// the policies are presented in.
func TestTableLookupIsOrderIndependent(t *testing.T) {
	classes := testClasses(t)

	first := policy("prod", "a", v2alpha1.QoSEgressRule{QoSClassRefs: classRefs("voice")})
	second := policy("prod", "b", v2alpha1.QoSEgressRule{QoSClassRefs: classRefs("tied-with-voice")})
	flow := Flow{Dst: netip.MustParseAddr("10.0.0.1"), Proto: api.ProtoTCP, DstPort: 80}

	forward, errs := NewTable([]*v2alpha1.CiliumQoSPolicy{first, second}, classes)
	require.Empty(t, errs)
	reverse, errs := NewTable([]*v2alpha1.CiliumQoSPolicy{second, first}, classes)
	require.Empty(t, errs)

	assert.Equal(t, forward.Lookup(flow), reverse.Lookup(flow))
}

func TestNewTableReportsBrokenRules(t *testing.T) {
	classes := testClasses(t)

	t.Run("unknown class reference drops that class only", func(t *testing.T) {
		table, errs := NewTable([]*v2alpha1.CiliumQoSPolicy{
			policy("prod", "mixed", v2alpha1.QoSEgressRule{
				QoSClassRefs: classRefs("voice", "does-not-exist"),
			}),
		}, classes)

		require.Len(t, errs, 1)
		assert.ErrorContains(t, errs[0], `unknown or unresolved class "does-not-exist"`)

		marking := table.Lookup(Flow{Dst: netip.MustParseAddr("10.0.0.1"), Proto: api.ProtoTCP, DstPort: 80})
		require.NotNil(t, marking.DSCP)
		assert.Equal(t, uint8(46), *marking.DSCP)
	})

	t.Run("a rule with no usable class is dropped", func(t *testing.T) {
		table, errs := NewTable([]*v2alpha1.CiliumQoSPolicy{
			policy("prod", "broken", v2alpha1.QoSEgressRule{
				QoSClassRefs: classRefs("does-not-exist"),
			}),
		}, classes)

		require.Len(t, errs, 1)
		assert.True(t, table.Lookup(Flow{Dst: netip.MustParseAddr("10.0.0.1"), Proto: api.ProtoTCP, DstPort: 80}).IsZero())
	})

	t.Run("an invalid port range is reported", func(t *testing.T) {
		_, errs := NewTable([]*v2alpha1.CiliumQoSPolicy{
			policy("prod", "bad-range", v2alpha1.QoSEgressRule{
				ToPorts:      ports(v2alpha1.QoSPortProtocol{Port: "5000", EndPort: 4000}),
				QoSClassRefs: classRefs("voice"),
			}),
		}, classes)

		require.Len(t, errs, 1)
		assert.ErrorContains(t, errs[0], "endPort 4000 is not in [5000, 65535]")
	})
}

func TestSelectsPod(t *testing.T) {
	p := policy("prod", "payment")
	p.Spec.PodSelector = &slimv1.LabelSelector{
		MatchLabels: map[string]string{"app": "payment-processor"},
	}

	t.Run("matching labels in the policy namespace", func(t *testing.T) {
		selects, err := SelectsPod(p, "prod", map[string]string{"app": "payment-processor", "tier": "backend"})
		require.NoError(t, err)
		assert.True(t, selects)
	})

	t.Run("matching labels in another namespace", func(t *testing.T) {
		selects, err := SelectsPod(p, "staging", map[string]string{"app": "payment-processor"})
		require.NoError(t, err)
		assert.False(t, selects)
	})

	t.Run("non-matching labels", func(t *testing.T) {
		selects, err := SelectsPod(p, "prod", map[string]string{"app": "other"})
		require.NoError(t, err)
		assert.False(t, selects)
	})

	t.Run("empty selector selects the whole namespace", func(t *testing.T) {
		selects, err := SelectsPod(policy("prod", "all"), "prod", map[string]string{"app": "anything"})
		require.NoError(t, err)
		assert.True(t, selects)
	})
}
