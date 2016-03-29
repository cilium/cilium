package daemon

import (
	"encoding/json"

	"github.com/noironetworks/cilium-net/common"
	"github.com/noironetworks/cilium-net/common/types"

	consulAPI "github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/hashicorp/consul/api"
	. "github.com/noironetworks/cilium-net/Godeps/_workspace/src/gopkg.in/check.v1"
)

var (
	lbls           = createLbls()
	lbls2          = createLbls2()
	wantSecCtxLbls = types.SecCtxLabels{
		ID:       123,
		RefCount: 1,
		Labels:   lbls,
	}
)

func createLbls() types.Labels {
	lbls := []types.Label{
		types.NewLabel("foo", "bar", "cilium"),
		types.NewLabel("foo2", "=bar2", "cilium"),
		types.NewLabel("key", "", "cilium"),
		types.NewLabel("foo==", "==", "cilium"),
		types.NewLabel(`foo\\=`, `\=`, "cilium"),
		types.NewLabel(`//=/`, "", "cilium"),
		types.NewLabel(`%`, `%ed`, "cilium"),
	}
	return map[string]*types.Label{
		"foo":    &lbls[0],
		"foo2":   &lbls[1],
		"key":    &lbls[2],
		"foo==":  &lbls[3],
		`foo\\=`: &lbls[4],
		`//=/`:   &lbls[5],
		`%`:      &lbls[6],
	}
}

func createLbls2() types.Labels {
	lbls := []types.Label{
		types.NewLabel("foo", "bar", "cilium"),
		types.NewLabel("foo2", "=bar2", "cilium"),
	}
	return map[string]*types.Label{
		"foo":  &lbls[0],
		"foo2": &lbls[1],
	}
}

func (ds *DaemonSuite) SetUpTest(c *C) {
	consulConfig := consulAPI.DefaultConfig()
	consulConfig.Address = "127.0.0.1:8501"
	daemonConf := Config{
		LibDir:             "",
		LXCMap:             nil,
		NodeAddress:        nil,
		ConsulConfig:       consulConfig,
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
	c.Assert(err, Equals, nil)
	c.Assert(id, Equals, common.FirstFreeID)

	secCtxLbl, new, err := ds.d.PutLabels(lbls)
	c.Assert(err, Equals, nil)
	c.Assert(secCtxLbl.ID, Equals, 1)
	c.Assert(secCtxLbl.RefCount, Equals, 1)
	c.Assert(new, Equals, true)

	secCtxLbl, new, err = ds.d.PutLabels(lbls)
	c.Assert(err, Equals, nil)
	c.Assert(secCtxLbl.ID, Equals, 1)
	c.Assert(secCtxLbl.RefCount, Equals, 2)
	c.Assert(new, Equals, false)

	secCtxLbl, new, err = ds.d.PutLabels(lbls2)
	c.Assert(err, Equals, nil)
	c.Assert(secCtxLbl.ID, Equals, 2)
	c.Assert(secCtxLbl.RefCount, Equals, 1)
	c.Assert(new, Equals, true)

	secCtxLbl, new, err = ds.d.PutLabels(lbls2)
	c.Assert(err, Equals, nil)
	c.Assert(secCtxLbl.ID, Equals, 2)
	c.Assert(secCtxLbl.RefCount, Equals, 2)
	c.Assert(new, Equals, false)

	secCtxLbl, new, err = ds.d.PutLabels(lbls)
	c.Assert(err, Equals, nil)
	c.Assert(secCtxLbl.ID, Equals, 1)
	c.Assert(secCtxLbl.RefCount, Equals, 3)
	c.Assert(new, Equals, false)

	//Get labels from ID
	gotSecCtxLbl, err := ds.d.GetLabels(1)
	c.Assert(err, Equals, nil)
	wantSecCtxLbls.ID = 1
	wantSecCtxLbls.Labels = lbls
	wantSecCtxLbls.RefCount = 3
	c.Assert(*gotSecCtxLbl, DeepEquals, wantSecCtxLbls)

	gotSecCtxLbl, err = ds.d.GetLabels(2)
	c.Assert(err, Equals, nil)
	wantSecCtxLbls.ID = 2
	wantSecCtxLbls.Labels = lbls2
	wantSecCtxLbls.RefCount = 2
	c.Assert(*gotSecCtxLbl, DeepEquals, wantSecCtxLbls)
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
