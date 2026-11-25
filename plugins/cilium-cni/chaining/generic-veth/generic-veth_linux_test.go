// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package genericveth

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	clientapi "github.com/cilium/cilium/api/v1/client"
	"github.com/cilium/cilium/api/v1/client/endpoint"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/testutils"
	testutilsnetns "github.com/cilium/cilium/pkg/testutils/netns"
	chainingapi "github.com/cilium/cilium/plugins/cilium-cni/chaining/api"
	"github.com/cilium/cilium/plugins/cilium-cni/types"
)

type fakeEndpointClient struct {
	endpoint.ClientService
	createdEp *models.EndpointChangeRequest
}

func (f *fakeEndpointClient) PutEndpointID(params *endpoint.PutEndpointIDParams, _ ...endpoint.ClientOption) (*endpoint.PutEndpointIDCreated, error) {
	f.createdEp = params.Endpoint
	return &endpoint.PutEndpointIDCreated{Payload: &models.Endpoint{}}, nil
}

func TestPrivilegedGenericVethChainerAddNetnsCookie(t *testing.T) {
	testutils.PrivilegedTest(t)

	hostNS := testutilsnetns.NewNetNS(t)
	podNS := testutilsnetns.NewNetNS(t)

	var hostCookie uint64
	require.NoError(t, hostNS.Do(func() error {
		veth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: "veth-host"},
			PeerName:  "veth-pod",
		}
		if err := netlink.LinkAdd(veth); err != nil {
			return err
		}
		peer, err := safenetlink.LinkByName("veth-pod")
		if err != nil {
			return err
		}
		if err := netlink.LinkSetNsFd(peer, podNS.FD()); err != nil {
			return err
		}
		hostCookie, err = netns.GetNetNSCookie()
		return err
	}))

	var podCookie uint64
	require.NoError(t, podNS.Do(func() error {
		peer, err := safenetlink.LinkByName("veth-pod")
		if err != nil {
			return err
		}
		addr, err := netlink.ParseAddr("10.0.0.2/24")
		if err != nil {
			return err
		}
		if err := netlink.AddrAdd(peer, addr); err != nil {
			return err
		}
		podCookie, err = netns.GetNetNSCookie()
		return err
	}))
	require.NotZero(t, podCookie)
	require.NotEqual(t, hostCookie, podCookie)

	fakeEndpoint := &fakeEndpointClient{}
	cli := &client.Client{
		CiliumAPI: clientapi.CiliumAPI{
			Endpoint: fakeEndpoint,
		},
	}

	pluginCtx := chainingapi.PluginContext{
		Logger: hivetest.Logger(t),
		Args: &skel.CmdArgs{
			ContainerID: "test-container",
			Netns:       fmt.Sprintf("/proc/self/fd/%d", podNS.FD()),
			IfName:      "veth-pod",
		},
		CniArgs: &types.ArgsSpec{},
		NetConf: &types.NetConf{
			NetConf: cniTypes.NetConf{
				CNIVersion: "0.4.0",
				RawPrevResult: map[string]any{
					"cniVersion": "0.4.0",
				},
			},
		},
		CiliumConf: &models.DaemonConfigurationStatus{},
	}

	chainer := &GenericVethChainer{}
	require.NoError(t, hostNS.Do(func() error {
		_, err := chainer.Add(t.Context(), pluginCtx, cli)
		return err
	}))

	require.NotNil(t, fakeEndpoint.createdEp)
	require.Equal(t, strconv.FormatUint(podCookie, 10), fakeEndpoint.createdEp.NetnsCookie)
}
