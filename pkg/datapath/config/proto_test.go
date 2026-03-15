package config

import (
	"testing"

	config_latest "github.com/cilium/cilium/pkg/datapath/config/latest"
	"github.com/stretchr/testify/require"
)

func TestAny(t *testing.T) {
	msg, err := Any(&config_latest.BPFHost{})
	require.NoError(t, err)
	require.NotNil(t, msg)
	msg, err = Any(&config_latest.BPFLXC{})
	require.NoError(t, err)
	require.NotNil(t, msg)
	msg, err = Any(&config_latest.BPFOverlay{})
	require.NoError(t, err)
	require.NotNil(t, msg)
	msg, err = Any(&config_latest.BPFSock{})
	require.NoError(t, err)
	require.NotNil(t, msg)
	msg, err = Any(&config_latest.BPFWireguard{})
	require.NoError(t, err)
	require.NotNil(t, msg)
	msg, err = Any(&config_latest.BPFXDP{})
	require.NoError(t, err)
	require.NotNil(t, msg)
	msg, err = Any([]any{&config_latest.BPFHost{}})
	require.NoError(t, err)
	require.NotNil(t, msg)
	msg, err = Any([]any{&config_latest.BPFHost{}, &config_latest.BPFLXC{}})
	require.Error(t, err)
	require.Nil(t, msg)
	msg, err = Any(nil)
	require.Error(t, err)
	require.Nil(t, msg)
	msg, err = Any((*config_latest.BPFHost)(nil))
	require.NoError(t, err)
	require.NotNil(t, msg)
	msg, err = Any([]any{nil})
	require.Error(t, err)
	require.Nil(t, msg)
	msgSlice, err := Any([]any{&config_latest.BPFHost{}})
	require.NoError(t, err)
	msgNoSlice, err := Any(&config_latest.BPFHost{})
	require.NoError(t, err)
	require.Equal(t, msgNoSlice, msgSlice)
}
