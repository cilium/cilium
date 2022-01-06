// SPDX-License-Identifier: Apache-2.0
// Copyright 2019 Authors of Cilium

//go:build !privileged_tests
// +build !privileged_tests

package types

import (
	"os"
	"path"
	"testing"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	"gopkg.in/check.v1"

	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	azureTypes "github.com/cilium/cilium/pkg/azure/types"
	"github.com/cilium/cilium/pkg/checker"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type CNITypesSuite struct{}

var _ = check.Suite(&CNITypesSuite{})

func testConfRead(c *check.C, confContent string, netconf *NetConf) {
	dir, err := os.MkdirTemp("", "cilium-cnitype-testsuite")
	c.Assert(err, check.IsNil)
	defer os.RemoveAll(dir)

	p := path.Join(dir, "conf1")
	err = os.WriteFile(p, []byte(confContent), 0644)
	c.Assert(err, check.IsNil)

	netConf, err := ReadNetConf(p)
	c.Assert(err, check.IsNil)

	c.Assert(netConf, checker.DeepEquals, netconf)
}

func (t *CNITypesSuite) TestReadCNIConf(c *check.C) {
	confFile1 := `
{
  "name": "cilium",
  "type": "cilium-cni"
}
`

	netConf1 := NetConf{
		NetConf: cnitypes.NetConf{
			Name: "cilium",
			Type: "cilium-cni",
		},
	}
	testConfRead(c, confFile1, &netConf1)

	confFile2 := `
{
  "name": "cilium",
  "type": "cilium-cni",
  "mtu": 9000
}
`

	netConf2 := NetConf{
		NetConf: cnitypes.NetConf{
			Name: "cilium",
			Type: "cilium-cni",
		},
		MTU: 9000,
	}
	testConfRead(c, confFile2, &netConf2)
}

func (t *CNITypesSuite) TestReadCNIConfENIWithPlugins(c *check.C) {
	confFile1 := `
{
  "cniVersion":"0.3.1",
  "name":"cilium",
  "plugins": [
    {
      "cniVersion":"0.3.1",
      "type":"cilium-cni",
      "eni": {
        "pre-allocate": 5,
        "first-interface-index":1,
        "security-groups":[
          "sg-xxx"
        ],
        "subnet-ids":[
          "subnet-xxx"
        ],
        "subnet-tags":{
          "foo":"true"
        }
      }
    }
  ]
}
`
	firstInterfaceIndex := 1
	netConf1 := NetConf{
		NetConf: cnitypes.NetConf{
			CNIVersion: "0.3.1",
			Type:       "cilium-cni",
		},
		ENI: eniTypes.ENISpec{
			PreAllocate:         5,
			FirstInterfaceIndex: &firstInterfaceIndex,
			SecurityGroups:      []string{"sg-xxx"},
			SubnetIDs:           []string{"subnet-xxx"},
			SubnetTags: map[string]string{
				"foo": "true",
			},
		},
	}
	testConfRead(c, confFile1, &netConf1)
}

func (t *CNITypesSuite) TestReadCNIConfENI(c *check.C) {
	confFile1 := `
{
  "name": "cilium",
  "type": "cilium-cni",
  "eni": {
    "instance-type": "m4.xlarge",
    "pre-allocate": 16,
    "first-interface-index": 2,
    "security-groups": [ "sg1", "sg2" ],
    "subnet-ids":[
      "subnet-1",
      "subnet-2"
    ],
    "subnet-tags": {
      "key1": "val1",
      "key2": "val2"
    },
    "vpc-id": "vpc-1",
    "availability-zone": "us-west1"
  }
}
`
	firstInterfaceIndex := 2
	netConf1 := NetConf{
		NetConf: cnitypes.NetConf{
			Name: "cilium",
			Type: "cilium-cni",
		},
		ENI: eniTypes.ENISpec{
			InstanceType:        "m4.xlarge",
			PreAllocate:         16,
			FirstInterfaceIndex: &firstInterfaceIndex,
			SecurityGroups:      []string{"sg1", "sg2"},
			SubnetIDs:           []string{"subnet-1", "subnet-2"},
			SubnetTags: map[string]string{
				"key1": "val1",
				"key2": "val2",
			},
			VpcID:            "vpc-1",
			AvailabilityZone: "us-west1",
		},
	}
	testConfRead(c, confFile1, &netConf1)
}

func (t *CNITypesSuite) TestReadCNIConfENIv2WithPlugins(c *check.C) {
	confFile1 := `
{
  "cniVersion":"0.3.1",
  "name":"cilium",
  "plugins": [
    {
      "cniVersion":"0.3.1",
      "type":"cilium-cni",
      "eni": {
        "first-interface-index":1,
        "security-groups":[
          "sg-xxx"
        ],
        "subnet-ids":[
          "subnet-xxx"
        ],
        "subnet-tags":{
          "foo":"true"
        }
      },
      "ipam": {
        "pre-allocate": 5
      }
    }
  ]
}
`
	firstInterfaceIndex := 1
	netConf1 := NetConf{
		NetConf: cnitypes.NetConf{
			CNIVersion: "0.3.1",
			Type:       "cilium-cni",
		},
		ENI: eniTypes.ENISpec{
			FirstInterfaceIndex: &firstInterfaceIndex,
			SecurityGroups:      []string{"sg-xxx"},
			SubnetIDs:           []string{"subnet-xxx"},
			SubnetTags: map[string]string{
				"foo": "true",
			},
		},
		IPAM: ipamTypes.IPAMSpec{
			PreAllocate: 5,
		},
	}
	testConfRead(c, confFile1, &netConf1)
}

func (t *CNITypesSuite) TestReadCNIConfAzurev2WithPlugins(c *check.C) {
	confFile1 := `
{
  "cniVersion":"0.3.1",
  "name":"cilium",
  "plugins": [
    {
      "cniVersion":"0.3.1",
      "type":"cilium-cni",
      "azure": {
        "interface-name": "eth1"
      },
      "ipam": {
        "pre-allocate": 5
      }
    }
  ]
}
`
	netConf1 := NetConf{
		NetConf: cnitypes.NetConf{
			CNIVersion: "0.3.1",
			Type:       "cilium-cni",
		},
		Azure: azureTypes.AzureSpec{
			InterfaceName: "eth1",
		},
		IPAM: ipamTypes.IPAMSpec{
			PreAllocate: 5,
		},
	}
	testConfRead(c, confFile1, &netConf1)
}

func (t *CNITypesSuite) TestReadCNIConfError(c *check.C) {
	// Try to read errorneous CNI configuration file with MTU provided as
	// string instead of int
	errorConf := `
{
  "name": "cilium",
  "type": "cilium-cni",
  "mtu": "9000"
}
`

	dir, err := os.MkdirTemp("", "cilium-cnitype-testsuite")
	c.Assert(err, check.IsNil)
	defer os.RemoveAll(dir)

	p := path.Join(dir, "errorconf")
	err = os.WriteFile(p, []byte(errorConf), 0644)
	c.Assert(err, check.IsNil)

	_, err = ReadNetConf(p)
	c.Assert(err, check.Not(check.IsNil))
}
