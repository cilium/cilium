// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	awsMetadata "github.com/cilium/cilium/pkg/aws/metadata"
	awsTypes "github.com/cilium/cilium/pkg/aws/types"
	"github.com/cilium/cilium/pkg/defaults"
	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipam"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/time"
)

const (
	msgListed     = "ENI address listed in instance metadata"
	msgExpired    = "ENI address not listed in instance metadata, no longer tracking it"
	msgAllocating = "Allocating ENI address before instance metadata lists it"
)

type recordingHandler struct {
	mu      lock.Mutex
	records []slog.Record
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler            { return h }

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}

// logged returns the attributes of the records with message msg and clears the records.
func (h *recordingHandler) logged(msg string) []map[string]string {
	h.mu.Lock()
	defer h.mu.Unlock()

	var out []map[string]string
	for _, r := range h.records {
		if r.Message != msg {
			continue
		}
		attrs := map[string]string{}
		r.Attrs(func(a slog.Attr) bool {
			attrs[a.Key] = a.Value.String()
			return true
		})
		out = append(out, attrs)
	}
	h.records = nil
	return out
}

// fakeIMDS serves the addresses and prefixes listed per MAC.
type fakeIMDS struct {
	listed map[string]awsMetadata.InterfaceAddresses
	err    error
	calls  int
}

func (f *fakeIMDS) list(_ context.Context, m string) (awsMetadata.InterfaceAddresses, error) {
	f.calls++
	return f.listed[m], f.err
}

func (f *fakeIMDS) set(m string, ips []string, prefixes []string) {
	var res awsMetadata.InterfaceAddresses
	for _, ip := range ips {
		res.IPv4s = append(res.IPv4s, netip.MustParseAddr(ip))
	}
	for _, p := range prefixes {
		res.IPv4Prefixes = append(res.IPv4Prefixes, netip.MustParsePrefix(p))
	}
	f.listed[m] = res
}

const (
	testENIMAC = "06:ff:f7:8b:c3:95"
	testENIID  = "eni-0c42b94a5d2e954e7"
)

func newTestVisibility(t *testing.T) (*addressVisibility, *fakeIMDS, *recordingHandler, *time.Time) {
	t.Helper()
	imds := &fakeIMDS{listed: map[string]awsMetadata.InterfaceAddresses{}}
	h := &recordingHandler{}
	now := time.Date(2026, 10, 1, 1, 45, 3, 0, time.UTC)
	v := newAddressVisibility(slog.New(h), imds.list)
	v.now = func() time.Time { return now }
	v.sync()
	return v, imds, h, &now
}

func pending(v *addressVisibility) int {
	v.mu.Lock()
	defer v.mu.Unlock()
	n := 0
	for _, e := range v.entries {
		if e.pending {
			n++
		}
	}
	return n
}

func testENINode(addresses []iputil.Addr, prefixes []iputil.Prefix) *ciliumv2.CiliumNode {
	node := &ciliumv2.CiliumNode{}
	node.Status.ENI.ENIs = map[string]awsTypes.ENI{
		testENIID: {
			ID:        testENIID,
			MAC:       mac.MustParseMAC(testENIMAC),
			IP:        iputil.AddrFrom(netip.MustParseAddr("192.168.78.248")),
			Subnet:    awsTypes.AwsSubnet{CIDR: iputil.PrefixFrom(netip.MustParsePrefix("192.168.64.0/18"))},
			Addresses: addresses,
			Prefixes:  prefixes,
		},
	}
	return node
}

func TestAddressVisibilityDelayedListing(t *testing.T) {
	v, imds, h, now := newTestVisibility(t)
	node := testENINode(addrs("192.168.78.248", "192.168.73.13", "192.168.87.123"), nil)
	imds.set(testENIMAC, []string{"192.168.78.248", "192.168.73.13"}, nil)

	v.observe(node)
	*now = now.Add(time.Second)
	v.poll(t.Context())
	require.Equal(t, 1, pending(v))

	listed := h.logged(msgListed)
	require.Len(t, listed, 2)
	for _, l := range listed {
		require.Equal(t, testENIID, l[logfields.ENI])
		require.Equal(t, testENIMAC, l[logfields.MACAddr])
		require.Equal(t, "1s", l[logfields.Duration])
	}

	*now = now.Add(50 * time.Second)
	r := &resolver{visibility: v}
	_, err := r.ResolveRoutingMetadata(node, netip.MustParseAddr("192.168.87.123"), ipam.Pool(defaults.IPAMDefaultIPPool))
	require.NoError(t, err)
	_, err = r.ResolveRoutingMetadata(node, netip.MustParseAddr("192.168.73.13"), ipam.Pool(defaults.IPAMDefaultIPPool))
	require.NoError(t, err)
	require.Equal(t, []map[string]string{{
		logfields.IPAddr:   "192.168.87.123",
		logfields.CIDR:     "192.168.87.123/32",
		logfields.ENI:      testENIID,
		logfields.MACAddr:  testENIMAC,
		logfields.Duration: "51s",
	}}, h.logged(msgAllocating))

	*now = now.Add(42 * time.Second)
	imds.set(testENIMAC, []string{"192.168.78.248", "192.168.73.13", "192.168.87.123"}, nil)
	v.poll(t.Context())
	require.Zero(t, pending(v))
	require.Equal(t, []map[string]string{{
		logfields.CIDR:     "192.168.87.123/32",
		logfields.ENI:      testENIID,
		logfields.MACAddr:  testENIMAC,
		logfields.Duration: "1m33s",
	}}, h.logged(msgListed))

	calls := imds.calls
	v.poll(t.Context())
	require.Equal(t, calls, imds.calls, "no IMDS query without pending entries")

	v.allocating(netip.MustParseAddr("192.168.87.123"))
	require.Empty(t, h.logged(msgAllocating))
}

func TestAddressVisibilityNeverListed(t *testing.T) {
	v, imds, h, now := newTestVisibility(t)
	imds.set(testENIMAC, []string{"192.168.78.248"}, nil)
	v.observe(testENINode(addrs("192.168.78.248", "192.168.89.123"), nil))

	v.poll(t.Context())
	require.Equal(t, 1, pending(v))
	h.logged(msgListed)

	imds.err = errors.New("i/o timeout")
	*now = now.Add(time.Minute)
	v.poll(t.Context())
	require.Equal(t, 1, pending(v), "an IMDS error keeps entries pending")
	imds.err = nil

	*now = now.Add(addressVisibilityTimeout)
	calls := imds.calls
	v.poll(t.Context())
	require.Zero(t, pending(v))
	require.Equal(t, calls, imds.calls)
	require.Equal(t, []map[string]string{{
		logfields.CIDR:     "192.168.89.123/32",
		logfields.ENI:      testENIID,
		logfields.MACAddr:  testENIMAC,
		logfields.Duration: "6m0s",
	}}, h.logged(msgExpired))
	require.Empty(t, h.logged(msgListed))
}

func TestAddressVisibilityDelegatedPrefix(t *testing.T) {
	v, imds, h, now := newTestVisibility(t)
	prefix := "192.168.77.112/28"
	ips, err := iputil.PrefixToIps(prefix, 0)
	require.NoError(t, err)
	node := testENINode(addrs(append([]string{"192.168.78.248"}, ips...)...), prefixes(prefix))
	imds.set(testENIMAC, []string{"192.168.78.248"}, nil)

	v.observe(node)
	require.Len(t, v.entries, 2, "addresses inside a delegated prefix are tracked as the prefix")
	v.poll(t.Context())
	require.Equal(t, 1, pending(v))
	h.logged(msgListed)

	*now = now.Add(111 * time.Second)
	v.allocating(netip.MustParseAddr("192.168.77.115"))
	require.Equal(t, []map[string]string{{
		logfields.IPAddr:   "192.168.77.115",
		logfields.CIDR:     prefix,
		logfields.ENI:      testENIID,
		logfields.MACAddr:  testENIMAC,
		logfields.Duration: "1m51s",
	}}, h.logged(msgAllocating))

	*now = now.Add(30 * time.Second)
	imds.set(testENIMAC, []string{"192.168.78.248"}, []string{prefix})
	v.poll(t.Context())
	require.Zero(t, pending(v))
	require.Equal(t, []map[string]string{{
		logfields.CIDR:     prefix,
		logfields.ENI:      testENIID,
		logfields.MACAddr:  testENIMAC,
		logfields.Duration: "2m21s",
	}}, h.logged(msgListed))
}

func TestAddressVisibilityForgetsRemovedEntries(t *testing.T) {
	v, imds, h, now := newTestVisibility(t)
	v.observe(testENINode(addrs("192.168.78.248", "192.168.89.123"), nil))
	v.poll(t.Context())
	require.Equal(t, 2, pending(v))

	*now = now.Add(time.Minute)
	v.observe(testENINode(addrs("192.168.78.248"), nil))
	require.Len(t, v.entries, 1)

	*now = now.Add(time.Minute)
	v.observe(testENINode(addrs("192.168.78.248", "192.168.89.123"), nil))
	imds.set(testENIMAC, []string{"192.168.78.248", "192.168.89.123"}, nil)
	v.poll(t.Context())
	require.Zero(t, pending(v))
	listed := h.logged(msgListed)
	require.Len(t, listed, 2)
	for _, l := range listed {
		if l[logfields.CIDR] == "192.168.89.123/32" {
			require.Equal(t, "0s", l[logfields.Duration], "a re-added address is timed from its re-addition")
		}
	}

	v.observe(nil)
	require.Empty(t, v.entries)
}

func TestAddressVisibilityInitialListingIsBaseline(t *testing.T) {
	imds := &fakeIMDS{listed: map[string]awsMetadata.InterfaceAddresses{}}
	h := &recordingHandler{}
	v := newAddressVisibility(slog.New(h), imds.list)
	node := testENINode(addrs("192.168.78.248", "192.168.73.13"), nil)

	v.observe(node)
	r := &resolver{visibility: v}
	_, err := r.ResolveRoutingMetadata(node, netip.MustParseAddr("192.168.73.13"), ipam.Pool(defaults.IPAMDefaultIPPool))
	require.NoError(t, err)
	v.poll(t.Context())
	require.Zero(t, pending(v))
	require.Zero(t, imds.calls)
	require.Empty(t, h.logged(msgAllocating))

	v.sync()
	v.observe(testENINode(addrs("192.168.78.248", "192.168.73.13", "192.168.87.123"), nil))
	require.Equal(t, 1, pending(v))
}

func TestAddressVisibilityNeedsDebug(t *testing.T) {
	require.Nil(t, startAddressVisibility(slog.New(slog.DiscardHandler), nil, nil, nil))

	r := &resolver{}
	_, err := r.ResolveRoutingMetadata(testENINode(addrs("192.168.78.248", "192.168.73.13"), nil),
		netip.MustParseAddr("192.168.73.13"), ipam.Pool(defaults.IPAMDefaultIPPool))
	require.NoError(t, err)
}
