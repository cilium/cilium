// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"os"
	"path"
	"testing"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/stretchr/testify/require"

	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	azureTypes "github.com/cilium/cilium/pkg/azure/types"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
)

func testConfRead(t *testing.T, confContent string, netconf *NetConf) {
	dir, err := os.MkdirTemp("", "cilium-cnitype-testsuite")
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	p := path.Join(dir, "conf1")
	err = os.WriteFile(p, []byte(confContent), 0644)
	require.NoError(t, err)

	netConf, err := ReadNetConf(p)
	require.NoError(t, err)

	require.Equal(t, netConf, netconf)
}

func TestReadCNIConf(t *testing.T) {
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
	testConfRead(t, confFile1, &netConf1)

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
	testConfRead(t, confFile2, &netConf2)
}

func TestReadCNIConfENIWithPlugins(t *testing.T) {
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
        },
        "exclude-interface-tags":{
          "baz":"false"
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
			FirstInterfaceIndex: &firstInterfaceIndex,
			SecurityGroups:      []string{"sg-xxx"},
			SubnetIDs:           []string{"subnet-xxx"},
			SubnetTags: map[string]string{
				"foo": "true",
			},
			ExcludeInterfaceTags: map[string]string{
				"baz": "false",
			},
		},
	}
	testConfRead(t, confFile1, &netConf1)
}

func TestReadCNIConfENI(t *testing.T) {
	confFile1 := `
{
  "name": "cilium",
  "type": "cilium-cni",
  "eni": {
    "instance-type": "m4.xlarge",
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
    "exclude-interface-tags": {
      "key3": "val3",
      "key4": "val4"
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
			FirstInterfaceIndex: &firstInterfaceIndex,
			SecurityGroups:      []string{"sg1", "sg2"},
			SubnetIDs:           []string{"subnet-1", "subnet-2"},
			SubnetTags: map[string]string{
				"key1": "val1",
				"key2": "val2",
			},
			ExcludeInterfaceTags: map[string]string{
				"key3": "val3",
				"key4": "val4",
			},
			VpcID:            "vpc-1",
			AvailabilityZone: "us-west1",
		},
	}
	testConfRead(t, confFile1, &netConf1)
}

func TestReadCNIConfENIv2WithPlugins(t *testing.T) {
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
        },
        "exclude-interface-tags":{
          "bar":"false"
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
			ExcludeInterfaceTags: map[string]string{
				"bar": "false",
			},
		},
		IPAM: IPAM{
			IPAMSpec: ipamTypes.IPAMSpec{
				PreAllocate: 5,
			},
		},
	}
	testConfRead(t, confFile1, &netConf1)
}

func TestReadCNIConfAzurev2WithPlugins(t *testing.T) {
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
		IPAM: IPAM{
			IPAMSpec: ipamTypes.IPAMSpec{
				PreAllocate: 5,
			},
		},
	}
	testConfRead(t, confFile1, &netConf1)
}

func TestReadCNIConfIPAMType(t *testing.T) {
	confFile := `
{
  "cniVersion":"0.3.1",
  "name":"cilium",
  "plugins": [
    {
      "cniVersion":"0.3.1",
      "type":"cilium-cni",
      "ipam": {
        "type": "delegated-ipam"
      }
    }
  ]
}
`
	netConf := NetConf{
		NetConf: cnitypes.NetConf{
			CNIVersion: "0.3.1",
			Type:       "cilium-cni",
		},
		IPAM: IPAM{
			IPAM: cnitypes.IPAM{
				Type: "delegated-ipam",
			},
		},
	}
	testConfRead(t, confFile, &netConf)
}

func TestReadCNIConfError(t *testing.T) {
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
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	p := path.Join(dir, "errorconf")
	err = os.WriteFile(p, []byte(errorConf), 0644)
	require.NoError(t, err)

	_, err = ReadNetConf(p)
	require.Error(t, err)
}
