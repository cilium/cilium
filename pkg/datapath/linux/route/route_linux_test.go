// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package route

import (
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

func setup(tb testing.TB) {
	testutils.PrivilegedTest(tb)
}

func testReplaceNexthopRoute(t *testing.T, link netlink.Link, routerNet *net.IPNet) {
	route := Route{
		Table: 10,
	}
	// delete route in case it exists from a previous failed run
	deleteNexthopRoute(route, link, routerNet)

	// defer cleanup in case of failure
	defer deleteNexthopRoute(route, link, routerNet)

	replaced, err := replaceNexthopRoute(route, link, routerNet)
	require.Nil(t, err)
	require.Equal(t, true, replaced)

	// We expect routes to always be replaced
	replaced, err = replaceNexthopRoute(route, link, routerNet)
	require.Nil(t, err)
	require.Equal(t, true, replaced)

	err = deleteNexthopRoute(route, link, routerNet)
	require.Nil(t, err)
}

func TestReplaceNexthopRoute(t *testing.T) {
	setup(t)

	link, err := netlink.LinkByName("lo")
	require.Nil(t, err)

	_, routerNet, err := net.ParseCIDR("1.2.3.4/32")
	require.Nil(t, err)
	testReplaceNexthopRoute(t, link, routerNet)

	_, routerNet, err = net.ParseCIDR("f00d::a02:100:0:815b/128")
	require.Nil(t, err)
	testReplaceNexthopRoute(t, link, routerNet)
}

func testReplaceRoute(t *testing.T, prefixStr, nexthopStr string, lookupTest bool) {
	_, prefix, err := net.ParseCIDR(prefixStr)
	require.Nil(t, err)
	require.NotNil(t, prefix)

	nexthop := net.ParseIP(nexthopStr)
	require.NotNil(t, nexthop)

	rt := Route{
		Device:  "lo",
		Prefix:  *prefix,
		Nexthop: &nexthop,
	}

	// delete route in case it exists from a previous failed run
	Delete(rt)

	// Defer deletion of route and nexthop route to cleanup in case of failure
	defer Delete(rt)
	defer Delete(Route{
		Device: "lo",
		Prefix: *rt.getNexthopAsIPNet(),
		Scope:  netlink.SCOPE_LINK,
	})

	err = Upsert(rt)
	require.Nil(t, err)

	if lookupTest {
		// Account for minimal kernel race condition where route is not
		// yet available
		require.Nil(t, testutils.WaitUntil(func() bool {
			installedRoute, err := Lookup(rt)
			require.Nil(t, err)
			return installedRoute != nil
		}, 5*time.Second))
	}

	err = Delete(rt)
	require.Nil(t, err)
}

func TestReplaceRoute(t *testing.T) {
	setup(t)

	testReplaceRoute(t, "2.2.0.0/16", "1.2.3.4", true)
	// lookup test broken for IPv6 as long as use lo as device
	testReplaceRoute(t, "f00d::a02:200:0:0/96", "f00d::a02:100:0:815b", false)
}

func testReplaceRule(t *testing.T, mark uint32, from, to *net.IPNet, table int) {
	rule := Rule{Mark: mark, From: from, To: to, Table: table}

	// delete rule in case it exists from a previous failed run
	DeleteRule(netlink.FAMILY_V4, rule)

	rule.Priority = 1
	err := ReplaceRule(rule)
	require.Nil(t, err)

	exists, err := lookupRule(rule, netlink.FAMILY_V4)
	require.Nil(t, err)
	require.Equal(t, true, exists)

	rule.Mask++
	exists, err = lookupRule(rule, netlink.FAMILY_V4)
	require.Nil(t, err)
	require.Equal(t, false, exists)
	rule.Mask--

	err = DeleteRule(netlink.FAMILY_V4, rule)
	require.Nil(t, err)

	exists, err = lookupRule(rule, netlink.FAMILY_V4)
	require.Nil(t, err)
	require.Equal(t, false, exists)
}

func testReplaceRuleIPv6(t *testing.T, mark uint32, from, to *net.IPNet, table int) {
	rule := Rule{Mark: mark, From: from, To: to, Table: table}

	// delete rule in case it exists from a previous failed run
	DeleteRule(netlink.FAMILY_V6, rule)

	rule.Priority = 1
	err := ReplaceRuleIPv6(rule)
	require.Nil(t, err)

	exists, err := lookupRule(rule, netlink.FAMILY_V6)
	require.Nil(t, err)
	require.Equal(t, true, exists)

	err = DeleteRule(netlink.FAMILY_V6, rule)
	require.Nil(t, err)

	exists, err = lookupRule(rule, netlink.FAMILY_V6)
	require.Nil(t, err)
	require.Equal(t, false, exists)
}

func TestReplaceRule(t *testing.T) {
	setup(t)

	_, cidr1, err := net.ParseCIDR("10.10.0.0/16")
	require.Nil(t, err)
	testReplaceRule(t, 0xf00, nil, nil, 123)
	testReplaceRule(t, 0xf00, cidr1, nil, 124)
	testReplaceRule(t, 0, nil, cidr1, 125)
	testReplaceRule(t, 0, cidr1, cidr1, 126)
}

func TestReplaceRule6(t *testing.T) {
	setup(t)

	_, cidr1, err := net.ParseCIDR("beef::/48")
	require.Nil(t, err)
	testReplaceRuleIPv6(t, 0xf00, nil, nil, 123)
	testReplaceRuleIPv6(t, 0xf00, cidr1, nil, 124)
	testReplaceRuleIPv6(t, 0, nil, cidr1, 125)
	testReplaceRuleIPv6(t, 0, cidr1, cidr1, 126)
}

func TestRule_String(t *testing.T) {
	setup(t)

	_, fakeIP, _ := net.ParseCIDR("10.10.10.10/32")
	_, fakeIP2, _ := net.ParseCIDR("1.1.1.1/32")

	tests := []struct {
		name    string
		rule    Rule
		wantStr string
	}{
		{
			name: "contains from and to IPs",
			rule: Rule{
				From: fakeIP,
				To:   fakeIP2,
			},
			wantStr: "0: from 10.10.10.10/32 to 1.1.1.1/32 lookup 0 proto unspec",
		},
		{
			name: "contains priority",
			rule: Rule{
				Priority: 1,
			},
			wantStr: "1: from all to all lookup 0 proto unspec",
		},
		{
			name: "contains table",
			rule: Rule{
				Table: 1,
			},
			wantStr: "0: from all to all lookup 1 proto unspec",
		},
		{
			name: "contains mark and mask",
			rule: Rule{
				Mark: 1,
				Mask: 1,
			},
			wantStr: "0: from all to all lookup 0 mark 0x1 mask 0x1 proto unspec",
		},
		{
			name: "main table",
			rule: Rule{
				Table: unix.RT_TABLE_MAIN,
			},
			wantStr: "0: from all to all lookup main proto unspec",
		},
	}
	for _, tt := range tests {
		if diff := cmp.Diff(tt.wantStr, tt.rule.String()); diff != "" {
			t.Errorf("%s", diff)
		}
	}
}

func TestListRules(t *testing.T) {
	testutils.PrivilegedTest(t)

	testListRules4(t)
	testListRules6(t)
}

func testListRules4(t *testing.T) {
	_, fakeIP, _ := net.ParseCIDR("192.0.2.40/32")
	_, fakeIP2, _ := net.ParseCIDR("192.0.2.60/32")

	runListRules(t, netlink.FAMILY_V4, fakeIP, fakeIP2)
}

func testListRules6(t *testing.T) {
	_, fakeIP, _ := net.ParseCIDR("fd44:7089:ff32:712b:4000::/64")
	_, fakeIP2, _ := net.ParseCIDR("fd44:7089:ff32:712b:8000::/96")

	runListRules(t, netlink.FAMILY_V6, fakeIP, fakeIP2)
}

func runListRules(t *testing.T, family int, fakeIP, fakeIP2 *net.IPNet) {
	tests := []struct {
		name       string
		ruleFilter *Rule
		preRun     func() *netlink.Rule // Creates sample rule harness
		postRun    func(*netlink.Rule)  // Deletes sample rule harness
		setupWant  func(*netlink.Rule) ([]netlink.Rule, bool)
	}{
		{
			name:       "returns all rules",
			ruleFilter: nil,
			preRun:     func() *netlink.Rule { return nil },
			postRun:    func(r *netlink.Rule) {},
			setupWant: func(_ *netlink.Rule) ([]netlink.Rule, bool) {
				defaultRules, _ := ListRules(family, nil)
				return defaultRules, false
			},
		},
		{
			name:       "returns one rule filtered by From",
			ruleFilter: &Rule{From: fakeIP},
			preRun: func() *netlink.Rule {
				r := netlink.NewRule()
				r.Src = fakeIP
				r.Family = family
				r.Priority = 1 // Must add priority and table otherwise it's auto-assigned
				r.Table = 1
				addRule(t, r)
				return r
			},
			postRun: func(r *netlink.Rule) { delRule(t, r) },
			setupWant: func(r *netlink.Rule) ([]netlink.Rule, bool) {
				return []netlink.Rule{*r}, false
			},
		},
		{
			name:       "returns one rule filtered by To",
			ruleFilter: &Rule{To: fakeIP},
			preRun: func() *netlink.Rule {
				r := netlink.NewRule()
				r.Dst = fakeIP
				r.Family = family
				r.Priority = 1 // Must add priority and table otherwise it's auto-assigned
				r.Table = 1
				addRule(t, r)
				return r
			},
			postRun: func(r *netlink.Rule) { delRule(t, r) },
			setupWant: func(r *netlink.Rule) ([]netlink.Rule, bool) {
				return []netlink.Rule{*r}, false
			},
		},
		{
			name:       "returns two rules filtered by To",
			ruleFilter: &Rule{To: fakeIP},
			preRun: func() *netlink.Rule {
				r := netlink.NewRule()
				r.Dst = fakeIP
				r.Family = family
				r.Priority = 1 // Must add priority and table otherwise it's auto-assigned
				r.Table = 1
				addRule(t, r)

				rc := *r // Create almost identical copy
				rc.Src = fakeIP2
				addRule(t, &rc)

				return r
			},
			postRun: func(r *netlink.Rule) {
				delRule(t, r)

				rc := *r // Delete the almost identical copy
				rc.Src = fakeIP2
				delRule(t, &rc)
			},
			setupWant: func(r *netlink.Rule) ([]netlink.Rule, bool) {
				rs := []netlink.Rule{}
				rs = append(rs, *r)

				rc := *r // Append the almost identical copy
				rc.Src = fakeIP2
				rs = append(rs, rc)

				return rs, false
			},
		},
		{
			name:       "returns one rule filtered by From when two rules exist",
			ruleFilter: &Rule{From: fakeIP2},
			preRun: func() *netlink.Rule {
				r := netlink.NewRule()
				r.Dst = fakeIP
				r.Family = family
				r.Priority = 1 // Must add priority and table otherwise it's auto-assigned
				r.Table = 1
				addRule(t, r)

				rc := *r // Create almost identical copy
				rc.Src = fakeIP2
				addRule(t, &rc)

				return r
			},
			postRun: func(r *netlink.Rule) {
				delRule(t, r)

				rc := *r // Delete the almost identical copy
				rc.Src = fakeIP2
				delRule(t, &rc)
			},
			setupWant: func(r *netlink.Rule) ([]netlink.Rule, bool) {
				rs := []netlink.Rule{}
				// Do not append `r`

				rc := *r // Append the almost identical copy
				rc.Src = fakeIP2
				rs = append(rs, rc)

				return rs, false
			},
		},
		{
			name:       "returns rules with specific priority",
			ruleFilter: &Rule{Priority: 5},
			preRun: func() *netlink.Rule {
				r := netlink.NewRule()
				r.Src = fakeIP
				r.Family = family
				r.Priority = 5
				r.Table = 1
				addRule(t, r)

				for i := 2; i < 5; i++ {
					rc := *r // Create almost identical copy
					rc.Table = i
					addRule(t, &rc)
				}

				return r
			},
			postRun: func(r *netlink.Rule) {
				delRule(t, r)

				for i := 2; i < 5; i++ {
					rc := *r // Delete the almost identical copy
					rc.Table = i
					delRule(t, &rc)
				}
			},
			setupWant: func(r *netlink.Rule) ([]netlink.Rule, bool) {
				rs := []netlink.Rule{}
				rs = append(rs, *r)

				for i := 2; i < 5; i++ {
					rc := *r // Append the almost identical copy
					rc.Table = i
					rs = append(rs, rc)
				}

				return rs, false
			},
		},
		{
			name:       "returns rules filtered by Table",
			ruleFilter: &Rule{Table: 199},
			preRun: func() *netlink.Rule {
				r := netlink.NewRule()
				r.Src = fakeIP
				r.Family = family
				r.Priority = 1 // Must add priority otherwise it's auto-assigned
				r.Table = 199
				addRule(t, r)
				return r
			},
			postRun: func(r *netlink.Rule) { delRule(t, r) },
			setupWant: func(r *netlink.Rule) ([]netlink.Rule, bool) {
				return []netlink.Rule{*r}, false
			},
		},
		{
			name:       "returns rules filtered by Mask",
			ruleFilter: &Rule{Mask: 0x5},
			preRun: func() *netlink.Rule {
				r := netlink.NewRule()
				r.Src = fakeIP
				r.Family = family
				r.Priority = 1 // Must add priority and table otherwise it's auto-assigned
				r.Table = 1
				r.Mask = func() *uint32 { a := uint32(0x5); return &a }()
				addRule(t, r)
				return r
			},
			postRun: func(r *netlink.Rule) { delRule(t, r) },
			setupWant: func(r *netlink.Rule) ([]netlink.Rule, bool) {
				return []netlink.Rule{*r}, false
			},
		},
		{
			name:       "returns rules filtered by Mark",
			ruleFilter: &Rule{Mark: 0xbb},
			preRun: func() *netlink.Rule {
				r := netlink.NewRule()
				r.Src = fakeIP
				r.Family = family
				r.Priority = 1 // Must add priority, table, mask otherwise it's auto-assigned
				r.Table = 1
				r.Mask = func() *uint32 { a := uint32(0xff); return &a }()
				r.Mark = 0xbb
				addRule(t, r)
				return r
			},
			postRun: func(r *netlink.Rule) { delRule(t, r) },
			setupWant: func(r *netlink.Rule) ([]netlink.Rule, bool) {
				return []netlink.Rule{*r}, false
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns := netns.NewNetNS(t)
			require.NoError(t, ns.Do(func() error {
				rule := tt.preRun()
				rules, err := ListRules(family, tt.ruleFilter)
				tt.postRun(rule)

				wantRules, wantErr := tt.setupWant(rule)

				if diff := cmp.Diff(wantRules, rules); diff != "" {
					t.Errorf("expected len: %d, got: %d\n%s\n", len(wantRules), len(rules), diff)
				}
				require.Equal(t, err != nil, wantErr)

				return nil
			}))
		})
	}
}

func addRule(tb testing.TB, r *netlink.Rule) {
	if err := netlink.RuleAdd(r); err != nil {
		tb.Logf("Unable to add rule: %v", err)
	}
}

func delRule(tb testing.TB, r *netlink.Rule) {
	if err := netlink.RuleDel(r); err != nil {
		tb.Logf("Unable to delete rule: %v", err)
	}
}
