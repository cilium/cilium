// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

// func TestWriteClusterConfig(t *testing.T) {
// 	// store a copy of the current options we will be modifying so that they
// 	// can be restored later
// 	oldMaxConnectedClusters := option.Config.MaxConnectedClusters
// 	defer func() { option.Config.MaxConnectedClusters = oldMaxConnectedClusters }()

// 	option.Config.MaxConnectedClusters = 255
// 	l := NewLoader()
// 	assert.NoError(t, l.writeClusterConfigHeader(dirInfo.Output))

// 	// cluster_config values cannot be changed. attempt to update an existing value
// 	option.Config.MaxConnectedClusters = 511
// 	assert.NoError(t, l.writeClusterConfigHeader(dirInfo.Output))
// 	assert.Error(t, l.writeClusterConfigHeader(dirInfo.Output))

// }
