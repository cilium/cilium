// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package safenetlink

import (
	"io"
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/cilium/cilium/pkg/testutils/netns"
)

func Test_withRetryResult(t *testing.T) {
	// Test eventually successful
	retries := 0
	out, err := WithRetryResult(func() (string, error) {
		if retries < 3 {
			retries++
			return "", netlink.ErrDumpInterrupted
		}

		return "success", nil
	})
	require.NoError(t, err)
	require.Equal(t, "success", out)
	require.Equal(t, 3, retries)

	// Test eventually fails
	retries = 0
	out, err = WithRetryResult(func() (string, error) {
		if retries < 3 {
			retries++
			return "", netlink.ErrDumpInterrupted
		}

		return "failure", io.ErrUnexpectedEOF
	})
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.Equal(t, "failure", out)
	require.Equal(t, 3, retries)

	// Test eventually times out
	out, err = WithRetryResult(func() (string, error) {
		return "", netlink.ErrDumpInterrupted
	})
	require.True(t, wait.Interrupted(err))
	require.Empty(t, out)
}

func TestPrivilegedIdempotentDel(t *testing.T) {
	// Can't use testutils.PrivilegedTest due to import cycle
	// (testutils -> mac -> safenetlink).
	if os.Getenv("PRIVILEGED_TESTS") == "" {
		t.Skip("Set PRIVILEGED_TESTS to run this test")
	}

	t.Run("XfrmPolicyDel", func(t *testing.T) {
		ns := netns.NewNetNS(t)
		require.NoError(t, ns.Do(func() error {
			_, srcNet, _ := net.ParseCIDR("10.0.0.0/24")
			_, dstNet, _ := net.ParseCIDR("10.0.1.0/24")
			policy := &netlink.XfrmPolicy{
				Src: srcNet,
				Dst: dstNet,
				Dir: netlink.XFRM_DIR_OUT,
			}

			require.NoError(t, XfrmPolicyDel(policy))

			require.NoError(t, netlink.XfrmPolicyAdd(policy))
			require.NoError(t, XfrmPolicyDel(policy))
			require.NoError(t, XfrmPolicyDel(policy))

			return nil
		}))
	})

	t.Run("XfrmStateDel", func(t *testing.T) {
		ns := netns.NewNetNS(t)
		require.NoError(t, ns.Do(func() error {
			state := &netlink.XfrmState{
				Src:   net.ParseIP("10.0.0.1"),
				Dst:   net.ParseIP("10.0.0.2"),
				Proto: netlink.XFRM_PROTO_ESP,
				Mode:  netlink.XFRM_MODE_TUNNEL,
				Spi:   1,
				Auth: &netlink.XfrmStateAlgo{
					Name: "hmac(sha256)",
					Key:  make([]byte, 32),
				},
				Crypt: &netlink.XfrmStateAlgo{
					Name: "cbc(aes)",
					Key:  make([]byte, 16),
				},
			}

			require.NoError(t, XfrmStateDel(state))

			require.NoError(t, netlink.XfrmStateAdd(state))
			require.NoError(t, XfrmStateDel(state))
			require.NoError(t, XfrmStateDel(state))

			return nil
		}))
	})

	t.Run("RouteDel", func(t *testing.T) {
		ns := netns.NewNetNS(t)
		require.NoError(t, ns.Do(func() error {
			//nolint:forbidigo
			lo, err := netlink.LinkByName("lo")
			require.NoError(t, err)
			require.NoError(t, netlink.LinkSetUp(lo))

			_, dst, _ := net.ParseCIDR("192.168.99.0/24")
			route := &netlink.Route{
				LinkIndex: lo.Attrs().Index,
				Dst:       dst,
				Table:     100,
			}

			require.NoError(t, RouteDel(route))

			require.NoError(t, netlink.RouteAdd(route))
			require.NoError(t, RouteDel(route))
			require.NoError(t, RouteDel(route))

			return nil
		}))
	})
}
