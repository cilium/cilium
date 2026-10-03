// SPDX-License-Identifier: Apache-2.0
/* Copyright Authors of Cilium */

package main

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/datapathplugins"
)

func newTestServer() *datapathPluginServer {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return newDatapathPluginServer(logger)
}

func TestPrepareCollection_HostContext(t *testing.T) {
	s := newTestServer()

	req := &datapathplugins.PrepareCollectionRequest{
		AttachmentContext: &datapathplugins.AttachmentContext{
			Context: &datapathplugins.AttachmentContext_Host_{
				Host: &datapathplugins.AttachmentContext_Host{
					Iface: &datapathplugins.AttachmentContext_InterfaceInfo{
						Name: "eth0",
					},
				},
			},
		},
		Collection: &datapathplugins.PrepareCollectionRequest_CollectionSpec{
			Programs: map[string]*datapathplugins.PrepareCollectionRequest_CollectionSpec_ProgramSpec{
				"cil_from_netdev": {SectionName: "from-netdev/entry"},
				"cil_to_netdev":   {SectionName: "to-netdev/entry"},
				"other_prog":      {SectionName: "other/entry"},
			},
		},
	}

	resp, err := s.PrepareCollection(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.Cookie)
	assert.Len(t, resp.Hooks, 2)

	hookMap := make(map[string]datapathplugins.HookType)
	for _, h := range resp.Hooks {
		hookMap[h.Target] = h.Type
	}

	assert.Equal(t, datapathplugins.HookType_PRE, hookMap["cil_from_netdev"])
	assert.Equal(t, datapathplugins.HookType_POST, hookMap["cil_to_netdev"])
}

func TestPrepareCollection_LxcContext(t *testing.T) {
	s := newTestServer()

	req := &datapathplugins.PrepareCollectionRequest{
		AttachmentContext: &datapathplugins.AttachmentContext{
			Context: &datapathplugins.AttachmentContext_Lxc{
				Lxc: &datapathplugins.AttachmentContext_LXC{
					Iface: &datapathplugins.AttachmentContext_InterfaceInfo{
						Name: "lxc12345",
					},
					PodInfo: &datapathplugins.AttachmentContext_PodInfo{
						Name:      "test-pod",
						Namespace: "default",
					},
				},
			},
		},
		Collection: &datapathplugins.PrepareCollectionRequest_CollectionSpec{
			Programs: map[string]*datapathplugins.PrepareCollectionRequest_CollectionSpec_ProgramSpec{
				"cil_from_container": {SectionName: "from-container/entry"},
				"cil_to_container":   {SectionName: "to-container/entry"},
			},
		},
	}

	resp, err := s.PrepareCollection(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.Cookie)
	assert.Len(t, resp.Hooks, 2)

	hookMap := make(map[string]datapathplugins.HookType)
	for _, h := range resp.Hooks {
		hookMap[h.Target] = h.Type
	}

	assert.Equal(t, datapathplugins.HookType_PRE, hookMap["cil_from_container"])
	assert.Equal(t, datapathplugins.HookType_POST, hookMap["cil_to_container"])
}

func TestPrepareCollection_OverlayContext(t *testing.T) {
	s := newTestServer()

	req := &datapathplugins.PrepareCollectionRequest{
		AttachmentContext: &datapathplugins.AttachmentContext{
			Context: &datapathplugins.AttachmentContext_Overlay_{
				Overlay: &datapathplugins.AttachmentContext_Overlay{
					Iface: &datapathplugins.AttachmentContext_InterfaceInfo{
						Name: "cilium_geneve",
					},
				},
			},
		},
		Collection: &datapathplugins.PrepareCollectionRequest_CollectionSpec{
			Programs: map[string]*datapathplugins.PrepareCollectionRequest_CollectionSpec_ProgramSpec{
				"cil_from_overlay": {SectionName: "from-overlay/entry"},
				"cil_to_overlay":   {SectionName: "to-overlay/entry"},
			},
		},
	}

	resp, err := s.PrepareCollection(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.Cookie)
	assert.Len(t, resp.Hooks, 2)
}

func TestPrepareCollection_IgnoredContext(t *testing.T) {
	s := newTestServer()

	req := &datapathplugins.PrepareCollectionRequest{
		AttachmentContext: &datapathplugins.AttachmentContext{
			Context: &datapathplugins.AttachmentContext_Socket_{
				Socket: &datapathplugins.AttachmentContext_Socket{},
			},
		},
	}

	resp, err := s.PrepareCollection(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Empty(t, resp.Hooks)
}

func TestInstrumentCollection(t *testing.T) {
	s := newTestServer()

	req := &datapathplugins.InstrumentCollectionRequest{
		Cookie: "test-cookie-uuid",
		Hooks: []*datapathplugins.InstrumentCollectionRequest_Hook{
			{
				Target:  "cil_from_netdev",
				Type:    datapathplugins.HookType_PRE,
				PinPath: "/sys/fs/bpf/cilium/operations/test/hook0",
			},
			{
				Target:  "cil_to_netdev",
				Type:    datapathplugins.HookType_POST,
				PinPath: "/sys/fs/bpf/cilium/operations/test/hook1",
			},
			{
				Target:  "cil_from_container",
				Type:    datapathplugins.HookType_PRE,
				PinPath: "/sys/fs/bpf/cilium/operations/test/hook2",
			},
			{
				Target:  "cil_to_container",
				Type:    datapathplugins.HookType_POST,
				PinPath: "/sys/fs/bpf/cilium/operations/test/hook3",
			},
			{
				Target:  "cil_from_overlay",
				Type:    datapathplugins.HookType_PRE,
				PinPath: "/sys/fs/bpf/cilium/operations/test/hook4",
			},
			{
				Target:  "cil_to_overlay",
				Type:    datapathplugins.HookType_POST,
				PinPath: "/sys/fs/bpf/cilium/operations/test/hook5",
			},
		},
	}

	resp, err := s.InstrumentCollection(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Negative test: unsupported target or mismatched hook type must return an error
	badReq := &datapathplugins.InstrumentCollectionRequest{
		Cookie: "test-cookie-bad",
		Hooks: []*datapathplugins.InstrumentCollectionRequest_Hook{
			{
				Target:  "cil_from_netdev",
				Type:    datapathplugins.HookType_POST,
				PinPath: "/sys/fs/bpf/cilium/operations/test/bad",
			},
		},
	}
	_, err = s.InstrumentCollection(context.Background(), badReq)
	require.Error(t, err)
}
