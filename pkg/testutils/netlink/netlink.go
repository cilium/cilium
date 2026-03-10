// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package netlink

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/netns"
)

func MustLinkAdd(tb testing.TB, ns *netns.NetNS, link netlink.Link) {
	tb.Helper()

	require.NoError(tb, ns.Do(func() error {
		return netlink.LinkAdd(link)
	}))
}

func MustLinkSetUp(tb testing.TB, ns *netns.NetNS, link netlink.Link) {
	tb.Helper()

	require.NoError(tb, ns.Do(func() error {
		return netlink.LinkSetUp(link)
	}))
}

func MustLinkByName(tb testing.TB, ns *netns.NetNS, name string) netlink.Link {
	tb.Helper()

	var link netlink.Link
	require.NoError(tb, ns.Do(func() error {
		var err error
		link, err = safenetlink.LinkByName(name)
		return err
	}))
	return link
}

func MustAddrAdd(tb testing.TB, ns *netns.NetNS, link netlink.Link, addr netlink.Addr) {
	tb.Helper()

	require.NoError(tb, ns.Do(func() error {
		return netlink.AddrAdd(link, &addr)
	}))
}

func MustRouteListFiltered(tb testing.TB, ns *netns.NetNS, family int, filter *netlink.Route, filterMask uint64) []netlink.Route {
	tb.Helper()

	var routes []netlink.Route
	require.NoError(tb, ns.Do(func() error {
		var err error
		routes, err = safenetlink.RouteListFiltered(family, filter, filterMask)
		return err
	}))
	return routes
}

func MustXfrmStateList(tb testing.TB, ns *netns.NetNS, family int) []netlink.XfrmState {
	tb.Helper()

	var states []netlink.XfrmState
	require.NoError(tb, ns.Do(func() error {
		var err error
		states, err = safenetlink.XfrmStateList(family)
		return err
	}))
	return states
}

func MustXfrmStateGet(tb testing.TB, ns *netns.NetNS, state *netlink.XfrmState) *netlink.XfrmState {
	tb.Helper()

	var result *netlink.XfrmState
	require.NoError(tb, ns.Do(func() error {
		var err error
		result, err = netlink.XfrmStateGet(state)
		return err
	}))
	return result
}

func MustXfrmPolicyList(tb testing.TB, ns *netns.NetNS, family int) []netlink.XfrmPolicy {
	tb.Helper()

	var policies []netlink.XfrmPolicy
	require.NoError(tb, ns.Do(func() error {
		var err error
		policies, err = safenetlink.XfrmPolicyList(family)
		return err
	}))
	return policies
}

func MustXfrmPolicyGet(tb testing.TB, ns *netns.NetNS, policy *netlink.XfrmPolicy) *netlink.XfrmPolicy {
	tb.Helper()

	var result *netlink.XfrmPolicy
	require.NoError(tb, ns.Do(func() error {
		var err error
		result, err = netlink.XfrmPolicyGet(policy)
		return err
	}))
	return result
}
