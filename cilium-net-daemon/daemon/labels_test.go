package daemon

import (
	"encoding/json"

	"github.com/noironetworks/cilium-net/common"
	"github.com/noironetworks/cilium-net/common/types"

	consulAPI "github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/hashicorp/consul/api"
	. "github.com/noironetworks/cilium-net/Godeps/_workspace/src/gopkg.in/check.v1"
)

var (
	lbls = types.Labels{
		"foo":    types.NewLabel("foo", "bar", common.CiliumLabelSource),
		"foo2":   types.NewLabel("foo2", "=bar2", common.CiliumLabelSource),
		"key":    types.NewLabel("key", "", common.CiliumLabelSource),
		"foo==":  types.NewLabel("foo==", "==", common.CiliumLabelSource),
		`foo\\=`: types.NewLabel(`foo\\=`, `\=`, common.CiliumLabelSource),
		`//=/`:   types.NewLabel(`//=/`, "", common.CiliumLabelSource),
		`%`:      types.NewLabel(`%`, `%ed`, common.CiliumLabelSource),
	}
	lbls2 = types.Labels{
		"foo":  types.NewLabel("foo", "bar", common.CiliumLabelSource),
		"foo2": types.NewLabel("foo2", "=bar2", common.CiliumLabelSource),
	}
	wantSecCtxLbls = types.SecCtxLabel{
		ID:       123,
		RefCount: 1,
		Labels:   lbls,
	}
)

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
	c.Assert(secCtxLbl.ID, Equals, common.FirstFreeID)
	c.Assert(secCtxLbl.RefCount, Equals, 1)
	c.Assert(new, Equals, true)

	secCtxLbl, new, err = ds.d.PutLabels(lbls)
	c.Assert(err, Equals, nil)
	c.Assert(secCtxLbl.ID, Equals, common.FirstFreeID)
	c.Assert(secCtxLbl.RefCount, Equals, 2)
	c.Assert(new, Equals, false)

	secCtxLbl, new, err = ds.d.PutLabels(lbls2)
	c.Assert(err, Equals, nil)
	c.Assert(secCtxLbl.ID, Equals, common.FirstFreeID+1)
	c.Assert(secCtxLbl.RefCount, Equals, 1)
	c.Assert(new, Equals, true)

	secCtxLbl, new, err = ds.d.PutLabels(lbls2)
	c.Assert(err, Equals, nil)
	c.Assert(secCtxLbl.ID, Equals, common.FirstFreeID+1)
	c.Assert(secCtxLbl.RefCount, Equals, 2)
	c.Assert(new, Equals, false)

	secCtxLbl, new, err = ds.d.PutLabels(lbls)
	c.Assert(err, Equals, nil)
	c.Assert(secCtxLbl.ID, Equals, common.FirstFreeID)
	c.Assert(secCtxLbl.RefCount, Equals, 3)
	c.Assert(new, Equals, false)

	//Get labels from ID
	gotSecCtxLbl, err := ds.d.GetLabels(common.FirstFreeID)
	c.Assert(err, Equals, nil)
	wantSecCtxLbls.ID = common.FirstFreeID
	wantSecCtxLbls.Labels = lbls
	wantSecCtxLbls.RefCount = 3
	c.Assert(*gotSecCtxLbl, DeepEquals, wantSecCtxLbls)

	err = ds.d.DeleteLabelsByUUID(common.FirstFreeID)
	c.Assert(err, Equals, nil)
	gotSecCtxLbl, err = ds.d.GetLabels(common.FirstFreeID)
	c.Assert(err, Equals, nil)
	wantSecCtxLbls.ID = common.FirstFreeID
	wantSecCtxLbls.Labels = lbls
	wantSecCtxLbls.RefCount = 2
	c.Assert(*gotSecCtxLbl, DeepEquals, wantSecCtxLbls)

	gotSecCtxLbl, err = ds.d.GetLabels(common.FirstFreeID + 1)
	c.Assert(err, Equals, nil)
	wantSecCtxLbls.ID = common.FirstFreeID + 1
	wantSecCtxLbls.Labels = lbls2
	wantSecCtxLbls.RefCount = 2
	c.Assert(*gotSecCtxLbl, DeepEquals, wantSecCtxLbls)

	err = ds.d.DeleteLabelsByUUID(common.FirstFreeID)
	c.Assert(err, Equals, nil)
	gotSecCtxLbl, err = ds.d.GetLabels(common.FirstFreeID)
	wantSecCtxLbls.ID = common.FirstFreeID
	wantSecCtxLbls.Labels = lbls
	wantSecCtxLbls.RefCount = 1
	c.Assert(*gotSecCtxLbl, DeepEquals, wantSecCtxLbls)

	err = ds.d.DeleteLabelsByUUID(common.FirstFreeID)
	c.Assert(err, Equals, nil)
	gotSecCtxLbl, err = ds.d.GetLabels(common.FirstFreeID)
	c.Assert(err, Equals, nil)
	var emptySecCtxLblPtr *types.SecCtxLabel
	c.Assert(gotSecCtxLbl, Equals, emptySecCtxLblPtr)

	ds.d.setMaxID(common.FirstFreeID)
	c.Assert(err, Equals, nil)

	err = ds.d.DeleteLabelsByUUID(common.FirstFreeID)
	c.Assert(err, Equals, nil)
	gotSecCtxLbl, err = ds.d.GetLabels(common.FirstFreeID)
	c.Assert(err, Equals, nil)
	c.Assert(gotSecCtxLbl, Equals, emptySecCtxLblPtr)

	secCtxLbl, new, err = ds.d.PutLabels(lbls2)
	c.Assert(err, Equals, nil)
	c.Assert(secCtxLbl.ID, Equals, common.FirstFreeID+1)
	c.Assert(secCtxLbl.RefCount, Equals, 3)
	c.Assert(new, Equals, false)

	sha256sum, err := lbls2.SHA256Sum()
	c.Assert(err, Equals, nil)
	err = ds.d.DeleteLabelsBySHA256(sha256sum)
	c.Assert(err, Equals, nil)
	err = ds.d.DeleteLabelsByUUID(common.FirstFreeID + 1)
	c.Assert(err, Equals, nil)
	err = ds.d.DeleteLabelsByUUID(common.FirstFreeID + 1)
	c.Assert(err, Equals, nil)

	secCtxLbl, new, err = ds.d.PutLabels(lbls2)
	c.Assert(err, Equals, nil)
	c.Assert(secCtxLbl.ID, Equals, common.FirstFreeID)
	c.Assert(secCtxLbl.RefCount, Equals, 1)
	c.Assert(new, Equals, true)

	secCtxLbl, new, err = ds.d.PutLabels(lbls)
	c.Assert(err, Equals, nil)
	c.Assert(secCtxLbl.ID, Equals, common.FirstFreeID+1)
	c.Assert(secCtxLbl.RefCount, Equals, 1)
	c.Assert(new, Equals, true)
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
