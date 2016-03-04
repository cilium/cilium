package daemon

import (
	"encoding/json"
	"strings"

	"github.com/noironetworks/cilium-net/common"
	"github.com/noironetworks/cilium-net/common/types"

	consulAPI "github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/hashicorp/consul/api"
	. "github.com/noironetworks/cilium-net/Godeps/_workspace/src/gopkg.in/check.v1"
)

var (
	lbls = types.Labels{
		"foo":    "bar",
		"foo2":   "=bar2",
		"key":    "",
		"foo==":  "==",
		`foo\\=`: `\=`,
		`//=/`:   "",
		`%`:      `%ed`,
	}
	lbls2 = types.Labels{
		"foo":  "bar",
		"foo2": "=bar2",
	}
)

func (ds *DaemonSuite) SetUpTest(c *C) {
	daemonConf := Config{
		LibDir:             "",
		LXCMap:             nil,
		NodeAddress:        nil,
		ConsulConfig:       consulAPI.DefaultConfig(),
		DockerEndpoint:     "tcp://127.0.0.1",
		K8sEndpoint:        "tcp://127.0.0.1",
		ValidLabelPrefixes: nil,
	}

	d, err := NewDaemon(&daemonConf)
	c.Assert(err, Equals, nil)
	ds.d = d
	d.consul.KV().DeleteTree(common.OperationalPath, nil)
}

func (ds *DaemonSuite) TestLabels(c *C) {
	//Set up last free ID with zero
	id, err := ds.d.GetMaxID()
	c.Assert(strings.Contains(err.Error(), "unset"), Equals, true)

	id, err = ds.d.GetLabelsID(lbls)
	c.Assert(err, Equals, nil)
	c.Assert(id, Equals, 1)

	id, err = ds.d.GetLabelsID(lbls)
	c.Assert(err, Equals, nil)
	c.Assert(id, Equals, 1)

	id, err = ds.d.GetLabelsID(lbls2)
	c.Assert(err, Equals, nil)
	c.Assert(id, Equals, 2)

	id, err = ds.d.GetLabelsID(lbls2)
	c.Assert(err, Equals, nil)
	c.Assert(id, Equals, 2)

	id, err = ds.d.GetLabelsID(lbls)
	c.Assert(err, Equals, nil)
	c.Assert(id, Equals, 1)

	//Get labels from ID
	gotLabels, err := ds.d.GetLabels(1)
	c.Assert(err, Equals, nil)
	c.Assert(*gotLabels, DeepEquals, lbls)

	gotLabels, err = ds.d.GetLabels(2)
	c.Assert(err, Equals, nil)
	c.Assert(*gotLabels, DeepEquals, lbls2)
}

func (ds *DaemonSuite) TestMaxSetOfLabels(c *C) {
	//Set up last free ID with common.MaxSetOfLabels - 1
	kv := ds.d.consul.KV()
	byteJSON, err := json.Marshal((common.MaxSetOfLabels - 1))
	c.Assert(err, Equals, nil)
	p := &consulAPI.KVPair{Key: common.LastFreeIDKeyPath, Value: byteJSON}
	_, err = kv.Put(p, nil)
	c.Assert(err, Equals, nil)

	id, err := ds.d.GetMaxID()
	c.Assert(err, Equals, nil)
	c.Assert(id, Equals, (common.MaxSetOfLabels - 1))

	id, err = ds.d.GetLabelsID(lbls)
	c.Assert(err, Equals, nil)
	c.Assert(id, Equals, (common.MaxSetOfLabels - 1))

	_, err = ds.d.GetLabelsID(lbls2)
	c.Assert(strings.Contains(err.Error(), "maximum"), Equals, true)

	id, err = ds.d.GetLabelsID(lbls)
	c.Assert(err, Equals, nil)
	c.Assert(id, Equals, (common.MaxSetOfLabels - 1))
}

func (ds *DaemonSuite) TestGetMaxID(c *C) {
	kv := ds.d.consul.KV()
	byteJSON, err := json.Marshal((common.MaxSetOfLabels - 1))
	c.Assert(err, Equals, nil)
	p := &consulAPI.KVPair{Key: common.LastFreeIDKeyPath, Value: byteJSON}
	_, err = kv.Put(p, nil)
	c.Assert(err, Equals, nil)

	id, err := ds.d.GetMaxID()
	c.Assert(err, Equals, nil)
	c.Assert(id, Equals, (common.MaxSetOfLabels - 1))
}
