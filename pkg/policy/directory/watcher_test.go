// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package directory

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	policytypes "github.com/cilium/cilium/pkg/policy/types"
)

var policy1 = `
apiVersion: cilium.io/v2
kind: CiliumClusterWideNetworkPolicy
metadata:
  name: deny-egress-to-ip
spec:
  endpointSelector: {}
  egressDeny:
    - toCIDR:
        - "11.1.0.4/32"
  enableDefaultDeny:
    egress: false
`

var policy2 = `
apiVersion: cilium.io/v2
kind: CiliumClusterWideNetworkPolicy
metadata:
  name: deny-egress-to-ip
spec:
  endpointSelector: {}
  egressDeny:
    - toCIDR:
        - "10.0.0.5/32"
  enableDefaultDeny:
    egress: false
`

var invalidPolicy = `
apiVersion: cilium.io/v2
kind: CiliumClusterWideNetworkPolicy
metadata:
  name: deny-egress-to-ip
spec:
  endpointSelector:{}
  - 
  egressDeny:
    - toCIDR:
        - "68.63.129.16/32"
  enableDefaultDeny:
    egress: false
`

type policyMananger struct {
}

func newPolicyManager() *policyMananger {
	return &policyMananger{}
}

func (p *policyMananger) UpdatePolicy(u *policytypes.PolicyUpdate) {
	if u.DoneChan != nil {
		u.DoneChan <- 42
	}
}

func TestTranslateToCNPObject(t *testing.T) {
	policyMgr := newPolicyManager()
	p := newPolicyWatcher(PolicyWatcherParams{Logger: hivetest.Logger(t), Importer: policyMgr}, defaultConfig)

	// valid yaml to cnp object
	data := []byte(policy1)
	cnpObj, err := p.translateToCNPObject(data)
	require.NoError(t, err, "Expected no error but got:%v", err)
	require.NotNil(t, cnpObj, "Expected cnp object to be non nil")

	// invalid yaml to throw error
	data = []byte(invalidPolicy)
	cnpObj, err = p.translateToCNPObject(data)
	require.Error(t, err, "Expected error but its nil")
	require.Nil(t, cnpObj, "Expected cnp object to be nil but its non nil")
}

func TestAddToPolicyEngine(t *testing.T) {
	policyMgr := newPolicyManager()

	p := newPolicyWatcher(PolicyWatcherParams{Logger: hivetest.Logger(t), Importer: policyMgr}, defaultConfig)

	// validate addToPolicyEngine returns no error and updates map entry
	data := []byte(policy1)
	cnp, _ := p.translateToCNPObject(data)
	err := p.addToPolicyEngine(cnp, "test.yaml")
	require.NoError(t, err)
	require.Len(t, p.fileNameToCnpCache, 1)
	val := p.fileNameToCnpCache["test.yaml"]
	require.NotNil(t, val)
	require.Equal(t, cnp, val)

	// validate updating policy should be allowed and update same map entry
	data = []byte(policy2)
	cnp, _ = p.translateToCNPObject(data)
	err = p.addToPolicyEngine(cnp, "test.yaml")
	require.NoError(t, err, "Expect no error while add policy but got error:%v", err)
	val = p.fileNameToCnpCache["test.yaml"]
	require.NotNil(t, val)
	require.Equal(t, cnp, val)
}

func TestDeleteFromPolicyEngine(t *testing.T) {
	policyMgr := newPolicyManager()
	p := newPolicyWatcher(PolicyWatcherParams{Logger: hivetest.Logger(t), Importer: policyMgr}, defaultConfig)

	// validate deleteFromPolicyEngine returns no error and clears map entry
	data := []byte(policy1)
	cnp, _ := p.translateToCNPObject(data)
	err := p.addToPolicyEngine(cnp, "test.yaml")
	require.NoError(t, err)
	require.Len(t, p.fileNameToCnpCache, 1)
	err = p.deleteFromPolicyEngine("test.yaml")
	require.NoError(t, err)
	require.Empty(t, p.fileNameToCnpCache)

	// Delete non existent entry and validate if appropriate error returned
	p.addToPolicyEngine(cnp, "test2.yaml")
	err = p.deleteFromPolicyEngine("test.yaml")
	require.ErrorContains(t, err, "fileNameToCnp map entry doesn't exist",
		"Expected error `fileNameToCnp map entry doesn't exist` but got:%v", err)
	require.Len(t, p.fileNameToCnpCache, 1)
	err = p.deleteFromPolicyEngine("test2.yaml")
	require.NoError(t, err, "Expect no error while delete policy but got error:%v", err)
	require.Empty(t, p.fileNameToCnpCache)
}
