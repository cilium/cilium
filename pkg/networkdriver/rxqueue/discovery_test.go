// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package rxqueue

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func installDiscoveryFakes(t *testing.T) (*fakeNetlink, *netlink.Netkit) {
	t.Helper()
	fake := newFakeNetlink(8, 4)
	fake.install(t)
	fake.links[testPhysicalIfName] = &netlink.Device{LinkAttrs: *fake.links[testPhysicalIfName].Attrs()}
	primary := &netlink.Netkit{LinkAttrs: netlink.LinkAttrs{
		Name: "lxc-test", Index: 30, ParentIndex: testPeerIndex, NetNsID: fakePodNetNSID,
	}}
	oldFamily, oldList, oldPrimary, oldHasParent := netlinkGenlFamilyGet, netlinkLinkList, netkitIsPrimary, netdevHasParent
	oldPeerProof := netkitPeersUnleased
	t.Cleanup(func() {
		netlinkGenlFamilyGet, netlinkLinkList, netkitIsPrimary = oldFamily, oldList, oldPrimary
		netdevHasParent = oldHasParent
		netkitPeersUnleased = oldPeerProof
	})
	netlinkGenlFamilyGet = func(string) (*netlink.GenlFamily, error) {
		return &netlink.GenlFamily{Ops: []netlink.GenlOp{{ID: nl.NETDEV_CMD_QUEUE_CREATE}}}, nil
	}
	netlinkLinkList = func() ([]netlink.Link, error) {
		return []netlink.Link{fake.links[testPhysicalIfName], primary}, nil
	}
	netkitIsPrimary = func(*netlink.Netkit) bool { return true }
	netkitPeersUnleased = func(map[leaseTarget]netlink.Link) bool { return false }
	netdevHasParent = func(link netlink.Link) (bool, error) { return link.Attrs().Index == testPhysicalIndex, nil }
	fake.leases[3] = &netlink.NetDevQueueLease{
		IfIndex: testPeerIndex, Queue: netlink.NetDevQueueID{ID: 1, Type: netlink.NetDevQueueTypeRx},
		NetNSID: fakePodNetNSID, NetNSIDSet: true,
	}
	fake.flows[1] = netlink.NetDevRxFlow{Action: netlink.NetDevRxFlowAction{Queue: 3}, Location: 1}
	return fake, primary
}

func TestResetLeasedRXQueueFlows(t *testing.T) {
	fake, primary := installDiscoveryFakes(t)
	// No configuration or claims are supplied. Only the live lease authorizes
	// cleanup; an unleased queue's orphan rule must remain untouched.
	fake.flows[2] = netlink.NetDevRxFlow{Action: netlink.NetDevRxFlowAction{Queue: 2}, Location: 2}
	ownershipChecks := 0
	require.NoError(t, ResetLeasedRXQueueFlows(t.Context(), func(link netlink.Link) (bool, error) {
		ownershipChecks++
		require.Same(t, primary, link)
		return true, nil
	}))
	require.Equal(t, 1, ownershipChecks)
	require.NotContains(t, fake.flows, uint32(1))
	require.Contains(t, fake.flows, uint32(2))
	// The fake exposes four real queues but allocates eight slots. Discovery
	// must stop at the first out-of-range queue, rather than failing startup.
	require.Equal(t, 1, fake.flowDeletes)
}

func TestResetLeasedRXQueueFlowsRejectsUnknownOwners(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(*fakeNetlink, *netlink.Netkit)
		owned  bool
		err    error
		text   string
	}{
		{name: "wrong peer index", mutate: func(f *fakeNetlink, _ *netlink.Netkit) { f.leases[3].IfIndex++ }, owned: true, text: "unknown or ambiguous"},
		{name: "wrong peer namespace", mutate: func(f *fakeNetlink, _ *netlink.Netkit) { f.leases[3].NetNSID++ }, owned: true, text: "unknown or ambiguous"},
		{name: "missing peer namespace", mutate: func(f *fakeNetlink, _ *netlink.Netkit) { f.leases[3].NetNSIDSet = false }, owned: true, text: "unknown or ambiguous"},
		{name: "not a Cilium netkit", text: "non-Cilium"},
		{name: "ownership query fails", err: unix.EIO, text: "failed to verify"},
		{name: "duplicate peer identity", mutate: func(f *fakeNetlink, p *netlink.Netkit) {
			netlinkLinkList = func() ([]netlink.Link, error) {
				return []netlink.Link{f.links[testPhysicalIfName], p, &netlink.Netkit{LinkAttrs: p.LinkAttrs}}, nil
			}
		}, owned: true, text: "unknown or ambiguous"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fake, primary := installDiscoveryFakes(t)
			known := *fake.leases[3]
			fake.leases[2] = &known
			fake.flows[2] = netlink.NetDevRxFlow{Action: netlink.NetDevRxFlowAction{Queue: 2}, Location: 2}
			if tt.mutate != nil {
				tt.mutate(fake, primary)
			}
			err := ResetLeasedRXQueueFlows(t.Context(), func(netlink.Link) (bool, error) { return tt.owned, tt.err })
			require.ErrorContains(t, err, tt.text)
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
			}
			require.Zero(t, fake.flowDeletes, "unknown ownership must not delete any rule")
		})
	}
}

func TestResetLeasedRXQueueFlowsSkipsCleanQueues(t *testing.T) {
	for _, tt := range []struct {
		name      string
		action    *netlink.NetDevRxFlowAction
		queryErr  error
		listErr   bool
		wantError bool
	}{
		{name: "no rules after endpoint deletion"},
		{name: "another queue", action: &netlink.NetDevRxFlowAction{Queue: 2}},
		{name: "virtual function", action: &netlink.NetDevRxFlowAction{Queue: 3, VF: 1}},
		{name: "drop", action: &netlink.NetDevRxFlowAction{Queue: 3, Drop: true}},
		{name: "wake on LAN", action: &netlink.NetDevRxFlowAction{Queue: 3, WakeOnLAN: true}},
		{name: "RSS needs ownership", action: &netlink.NetDevRxFlowAction{UsesRSSContext: true}, wantError: true},
		{name: "same queue needs ownership", action: &netlink.NetDevRxFlowAction{Queue: 3}, wantError: true},
		{name: "list error", queryErr: unix.EIO, listErr: true, wantError: true},
		{name: "action error", queryErr: unix.EIO, wantError: true},
		{name: "rule disappeared", queryErr: unix.ENOENT},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fake, _ := installDiscoveryFakes(t)
			if tt.action != nil {
				fake.flows[1] = netlink.NetDevRxFlow{Action: *tt.action, Location: 1}
			} else if tt.queryErr == nil {
				clear(fake.flows)
			}
			if tt.queryErr != nil {
				if tt.listErr {
					netlinkNetDevRxFlowList = func(string) ([]uint32, error) { return nil, tt.queryErr }
				} else {
					netlinkNetDevRxFlowActionGet = func(string, uint32) (*netlink.NetDevRxFlowAction, error) { return nil, tt.queryErr }
				}
			}
			err := ResetLeasedRXQueueFlows(t.Context(), func(netlink.Link) (bool, error) { return false, nil })
			if tt.wantError {
				require.Error(t, err)
				if tt.queryErr != nil {
					require.ErrorIs(t, err, tt.queryErr)
				}
			} else {
				require.NoError(t, err)
			}
			require.Zero(t, fake.flowDeletes, "unknown ownership must never authorize rule deletion")
		})
	}
}

func TestResetLeasedRXQueueFlowsDownDevice(t *testing.T) {
	for _, tt := range []struct {
		name       string
		locations  []uint32
		err        error
		ntuple     *netlink.NetDevFeature
		featureErr error
		wantError  bool
	}{
		{name: "no rules"},
		{name: "no ntuple capability", err: unix.EOPNOTSUPP, ntuple: &netlink.NetDevFeature{}},
		{name: "disabled ntuple filters are unknown", err: unix.EOPNOTSUPP, ntuple: &netlink.NetDevFeature{Hardware: true}, wantError: true},
		{name: "fixed active ntuple filters are unknown", err: unix.EOPNOTSUPP, ntuple: &netlink.NetDevFeature{Active: true}, wantError: true},
		{name: "missing ntuple feature is unknown", err: unix.EOPNOTSUPP, wantError: true},
		{name: "feature query failure", err: unix.EOPNOTSUPP, ntuple: &netlink.NetDevFeature{}, featureErr: unix.EIO, wantError: true},
		{name: "rules need inspection", locations: []uint32{1}, ntuple: &netlink.NetDevFeature{}, wantError: true},
		{name: "query failure", err: unix.EIO, ntuple: &netlink.NetDevFeature{}, wantError: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fake, _ := installDiscoveryFakes(t)
			fake.links[testPhysicalIfName].Attrs().Flags = 0
			if tt.ntuple != nil {
				fake.features[ntupleFeature] = *tt.ntuple
			}
			if tt.featureErr != nil {
				netlinkNetDevFeaturesGet = func(int) (map[string]netlink.NetDevFeature, error) {
					return fake.features, tt.featureErr
				}
			}
			netlinkNetDevRxFlowList = func(string) ([]uint32, error) { return tt.locations, tt.err }
			err := ResetLeasedRXQueueFlows(t.Context(), nil)
			if tt.wantError {
				require.Error(t, err)
				if tt.err == nil {
					require.ErrorContains(t, err, "bring it up")
				} else {
					require.ErrorIs(t, err, tt.err)
				}
			} else {
				require.NoError(t, err)
			}
			require.Zero(t, fake.flowDeletes)
		})
	}
}

func TestResetLeasedRXQueueFlowsUnavailable(t *testing.T) {
	for _, tt := range []struct {
		name string
		err  error
	}{{"no queue-create", nil}, {"no netdev family", unix.ENOENT}, {"unsupported family", unix.EOPNOTSUPP}} {
		t.Run(tt.name, func(t *testing.T) {
			installDiscoveryFakes(t)
			netlinkGenlFamilyGet = func(string) (*netlink.GenlFamily, error) { return &netlink.GenlFamily{}, tt.err }
			netlinkLinkList = func() ([]netlink.Link, error) { t.Fatal("old kernels need no lease scan"); return nil, nil }
			require.NoError(t, ResetLeasedRXQueueFlows(t.Context(), nil))
		})
	}
}

func TestResetLeasedRXQueueFlowsErrors(t *testing.T) {
	t.Run("physical device with custom rtnetlink kind", func(t *testing.T) {
		fake, _ := installDiscoveryFakes(t)
		fake.links[testPhysicalIfName] = &netlink.Dummy{LinkAttrs: *fake.links[testPhysicalIfName].Attrs()}
		require.NoError(t, ResetLeasedRXQueueFlows(t.Context(), func(netlink.Link) (bool, error) { return true, nil }))
		require.Equal(t, 1, fake.flowDeletes)
	})
	t.Run("parent inspection fails", func(t *testing.T) {
		fake, _ := installDiscoveryFakes(t)
		netdevHasParent = func(netlink.Link) (bool, error) { return false, unix.EIO }
		require.ErrorIs(t, ResetLeasedRXQueueFlows(t.Context(), nil), unix.EIO)
		require.Zero(t, fake.flowDeletes)
	})
	t.Run("no primary netkit", func(t *testing.T) {
		fake, _ := installDiscoveryFakes(t)
		netlinkLinkList = func() ([]netlink.Link, error) { return []netlink.Link{fake.links[testPhysicalIfName]}, nil }
		netlinkNetDevQueueGet = func(int, uint32, netlink.NetDevQueueType) (*netlink.NetDevQueue, error) {
			t.Fatal("without a primary netkit there can be no surviving Cilium lease")
			return nil, nil
		}
		require.NoError(t, ResetLeasedRXQueueFlows(t.Context(), nil))
		require.Zero(t, fake.flowDeletes)
	})
	t.Run("interface goes down during inspection", func(t *testing.T) {
		fake, _ := installDiscoveryFakes(t)
		netlinkNetDevQueueGet = func(int, uint32, netlink.NetDevQueueType) (*netlink.NetDevQueue, error) {
			fake.links[testPhysicalIfName].Attrs().Flags = 0
			return nil, unix.ENOENT
		}
		require.ErrorContains(t, ResetLeasedRXQueueFlows(t.Context(), nil), "bring it up")
		require.Zero(t, fake.flowDeletes)
	})
	t.Run("queue inspection", func(t *testing.T) {
		fake, _ := installDiscoveryFakes(t)
		netlinkNetDevQueueGet = func(int, uint32, netlink.NetDevQueueType) (*netlink.NetDevQueue, error) { return nil, unix.EIO }
		require.ErrorIs(t, ResetLeasedRXQueueFlows(t.Context(), nil), unix.EIO)
		require.Zero(t, fake.flowDeletes)
	})
	t.Run("rule withdrawal", func(t *testing.T) {
		installDiscoveryFakes(t)
		netlinkNetDevRxFlowDelete = func(string, uint32) error { return unix.EIO }
		require.ErrorIs(t, ResetLeasedRXQueueFlows(t.Context(), func(netlink.Link) (bool, error) { return true, nil }), unix.EIO)
	})
	t.Run("cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		require.ErrorIs(t, ResetLeasedRXQueueFlows(ctx, nil), context.Canceled)
	})
	t.Run("no permission", func(t *testing.T) {
		installDiscoveryFakes(t)
		netlinkGenlFamilyGet = func(string) (*netlink.GenlFamily, error) { return nil, unix.EPERM }
		require.ErrorIs(t, ResetLeasedRXQueueFlows(t.Context(), nil), unix.EPERM)
	})
	t.Run("interface list", func(t *testing.T) {
		installDiscoveryFakes(t)
		errFailure := errors.New("link dump failed")
		netlinkLinkList = func() ([]netlink.Link, error) { return nil, errFailure }
		require.ErrorIs(t, ResetLeasedRXQueueFlows(t.Context(), nil), errFailure)
	})
}

type fakePeerQueueReader struct {
	err     error
	queried []int
	closed  bool
}

func (r *fakePeerQueueReader) NetDevQueueGet(index int, id uint32, kind netlink.NetDevQueueType) (*netlink.NetDevQueue, error) {
	r.queried = append(r.queried, index)
	return &netlink.NetDevQueue{IfIndex: uint32(index), ID: id, Type: kind}, r.err
}

func (r *fakePeerQueueReader) Close() error { r.closed = true; return nil }

func installPeerProofFakes(t *testing.T) (map[leaseTarget]netlink.Link, *fakePeerQueueReader) {
	t.Helper()
	_, primary := installDiscoveryFakes(t)
	oldPath, oldOpen, oldID, oldReader := peerNamespacePath, peerNamespaceOpen, hostGetNetNSIDByFD, newPeerQueueReader
	t.Cleanup(func() {
		peerNamespacePath, peerNamespaceOpen, hostGetNetNSIDByFD, newPeerQueueReader = oldPath, oldOpen, oldID, oldReader
	})
	peerNamespacePath = t.TempDir()
	path := filepath.Join(peerNamespacePath, "pod-netns")
	require.NoError(t, os.WriteFile(path, nil, 0o600))
	// Open an ordinary fixture file, never a real namespace on the test host.
	peerNamespaceOpen = func(path string) (netns.NsHandle, error) {
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		return netns.NsHandle(fd), err
	}
	hostGetNetNSIDByFD = func(int) (int, error) { return fakePodNetNSID, nil }
	reader := &fakePeerQueueReader{err: unix.EINVAL}
	newPeerQueueReader = func(netns.NsHandle) (peerQueueReader, error) { return reader, nil }
	return map[leaseTarget]netlink.Link{{testPeerIndex, fakePodNetNSID}: primary}, reader
}

func TestProbeNetkitPeersUnleased(t *testing.T) {
	t.Run("all peers lack queue one", func(t *testing.T) {
		primaries, reader := installPeerProofFakes(t)
		primaries[leaseTarget{testPeerIndex + 1, fakePodNetNSID}] = &netlink.Netkit{}
		require.True(t, probeNetkitPeersUnleased(primaries))
		require.ElementsMatch(t, []int{testPeerIndex, testPeerIndex + 1}, reader.queried)
		require.True(t, reader.closed)
		netkitPeersUnleased = probeNetkitPeersUnleased
		netdevHasParent = func(netlink.Link) (bool, error) { t.Fatal("unleased peers need no NIC inspection"); return false, nil }
		require.NoError(t, ResetLeasedRXQueueFlows(t.Context(), nil))
	})
	for _, queryErr := range []error{nil, unix.ENOENT, unix.ENODEV, unix.EIO} {
		t.Run("queue proof "+fmt.Sprint(queryErr), func(t *testing.T) {
			primaries, reader := installPeerProofFakes(t)
			reader.err = queryErr
			require.False(t, probeNetkitPeersUnleased(primaries))
			require.True(t, reader.closed)
		})
	}
	t.Run("unproven peer falls back to physical inspection", func(t *testing.T) {
		_, reader := installPeerProofFakes(t)
		reader.err = unix.ENOENT
		netkitPeersUnleased = probeNetkitPeersUnleased
		require.NoError(t, ResetLeasedRXQueueFlows(t.Context(), func(netlink.Link) (bool, error) { return true, nil }))
	})
	for _, tt := range []struct {
		name   string
		mutate func(map[leaseTarget]netlink.Link)
	}{
		{"missing pin", func(map[leaseTarget]netlink.Link) {
			peerNamespaceOpen = func(string) (netns.NsHandle, error) { return -1, os.ErrNotExist }
		}},
		{"missing directory", func(map[leaseTarget]netlink.Link) { peerNamespacePath = filepath.Join(peerNamespacePath, "missing") }},
		{"unknown namespace", func(map[leaseTarget]netlink.Link) {
			hostGetNetNSIDByFD = func(int) (int, error) { return fakePodNetNSID + 1, nil }
		}},
		{"namespace query fails", func(map[leaseTarget]netlink.Link) { hostGetNetNSIDByFD = func(int) (int, error) { return 0, unix.EIO } }},
		{"pin cannot open", func(map[leaseTarget]netlink.Link) {
			peerNamespaceOpen = func(string) (netns.NsHandle, error) { return -1, unix.EACCES }
		}},
		{"socket cannot open", func(map[leaseTarget]netlink.Link) {
			newPeerQueueReader = func(netns.NsHandle) (peerQueueReader, error) { return nil, unix.EIO }
		}},
		{"ambiguous primary", func(p map[leaseTarget]netlink.Link) { p[leaseTarget{testPeerIndex, fakePodNetNSID}] = nil }},
		{"invalid peer", func(p map[leaseTarget]netlink.Link) { p[leaseTarget{0, fakePodNetNSID}] = &netlink.Netkit{} }},
		{"invalid signed peer", func(p map[leaseTarget]netlink.Link) { p[leaseTarget{^uint32(0), fakePodNetNSID}] = &netlink.Netkit{} }},
		{"invalid namespace", func(p map[leaseTarget]netlink.Link) { p[leaseTarget{testPeerIndex, -2}] = &netlink.Netkit{} }},
		{"one namespace missing", func(p map[leaseTarget]netlink.Link) {
			p[leaseTarget{testPeerIndex, fakePodNetNSID + 1}] = &netlink.Netkit{}
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			primaries, _ := installPeerProofFakes(t)
			tt.mutate(primaries)
			require.False(t, probeNetkitPeersUnleased(primaries))
		})
	}
	t.Run("missing namespace ID is inconclusive", func(t *testing.T) {
		primaries, _ := installPeerProofFakes(t)
		primary := primaries[leaseTarget{testPeerIndex, fakePodNetNSID}]
		primaries = map[leaseTarget]netlink.Link{{testPeerIndex, -1}: primary}
		netlinkNetDevQueueGet = func(index int, id uint32, kind netlink.NetDevQueueType) (*netlink.NetDevQueue, error) {
			t.Fatal("a missing namespace ID must not query a potentially unrelated host interface")
			return nil, unix.EIO
		}
		require.False(t, probeNetkitPeersUnleased(primaries))
	})
}
