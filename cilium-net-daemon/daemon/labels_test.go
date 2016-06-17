package daemon

import (
	"encoding/json"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/noironetworks/cilium-net/common"
	"github.com/noironetworks/cilium-net/common/types"

	consulAPI "github.com/hashicorp/consul/api"
	. "gopkg.in/check.v1"
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
		ID: 123,
		Containers: map[string]time.Time{
			"cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307": time.Now(),
		},
		Labels: lbls,
	}
)

func (ds *DaemonSuite) SetUpTest(c *C) {
	consulConfig := consulAPI.DefaultConfig()
	consulConfig.Address = "127.0.0.1:8501"
	_, ipv4range, err := net.ParseCIDR("10.1.2.0/16")
	c.Assert(err, IsNil)
	tempLibDir, err := ioutil.TempDir("", "cilium-test")
	c.Assert(err, IsNil)
	daemonConf := Config{
		LibDir:             tempLibDir,
		LXCMap:             nil,
		NodeAddress:        nil,
		ConsulConfig:       consulConfig,
		DockerEndpoint:     "tcp://127.0.0.1",
		K8sEndpoint:        "tcp://127.0.0.1",
		ValidLabelPrefixes: nil,
		IPv4Range:          ipv4range,
	}

	d1 := []byte("#!/usr/bin/env bash\necho \"OK\"\n")
	err = ioutil.WriteFile(filepath.Join(daemonConf.LibDir, "join_ep.sh"), d1, 0755)
	c.Assert(err, IsNil)

	d, err := NewDaemon(&daemonConf)
	c.Assert(err, Equals, nil)
	ds.d = d
	d.consul.KV().DeleteTree(common.OperationalPath, nil)
}

func (ds *DaemonSuite) TearDownTest(c *C) {
	os.RemoveAll(ds.d.conf.LibDir)
}

func (ds *DaemonSuite) TestLabels(c *C) {
	//Set up last free ID with zero
	id, err := ds.d.GetMaxID()
	c.Assert(err, Equals, nil)
	c.Assert(id, Equals, common.FirstFreeID)

	secCtxLbl, new, err := ds.d.PutLabels(lbls, "containerLabel1-1")
	c.Assert(err, Equals, nil)
	c.Assert(secCtxLbl.ID, Equals, common.FirstFreeID)
	c.Assert(secCtxLbl.RefCount(), Equals, 1)
	c.Assert(new, Equals, true)

	secCtxLbl, new, err = ds.d.PutLabels(lbls, "containerLabel1-2")
	c.Assert(err, Equals, nil)
	c.Assert(secCtxLbl.ID, Equals, common.FirstFreeID)
	c.Assert(secCtxLbl.RefCount(), Equals, 2)
	c.Assert(new, Equals, false)

	secCtxLbl, new, err = ds.d.PutLabels(lbls2, "containerLabel2-1")
	c.Assert(err, Equals, nil)
	c.Assert(secCtxLbl.ID, Equals, common.FirstFreeID+1)
	c.Assert(secCtxLbl.RefCount(), Equals, 1)
	c.Assert(new, Equals, true)

	secCtxLbl, new, err = ds.d.PutLabels(lbls2, "containerLabel2-2")
	c.Assert(err, Equals, nil)
	c.Assert(secCtxLbl.ID, Equals, common.FirstFreeID+1)
	c.Assert(secCtxLbl.RefCount(), Equals, 2)
	c.Assert(new, Equals, false)

	secCtxLbl, new, err = ds.d.PutLabels(lbls, "containerLabel1-3")
	c.Assert(err, Equals, nil)
	c.Assert(secCtxLbl.ID, Equals, common.FirstFreeID)
	c.Assert(secCtxLbl.RefCount(), Equals, 3)
	c.Assert(new, Equals, false)

	//Get labels from ID
	gotSecCtxLbl, err := ds.d.GetLabels(common.FirstFreeID)
	c.Assert(err, Equals, nil)
	wantSecCtxLbls.ID = common.FirstFreeID
	wantSecCtxLbls.Labels = lbls
	c.Assert(gotSecCtxLbl.ID, Equals, wantSecCtxLbls.ID)
	c.Assert(gotSecCtxLbl.Labels, DeepEquals, wantSecCtxLbls.Labels)
	c.Assert(gotSecCtxLbl.RefCount(), Equals, 3)

	err = ds.d.DeleteLabelsByUUID(common.FirstFreeID, "containerLabel1-1")
	c.Assert(err, Equals, nil)
	gotSecCtxLbl, err = ds.d.GetLabels(common.FirstFreeID)
	c.Assert(err, Equals, nil)
	wantSecCtxLbls.ID = common.FirstFreeID
	wantSecCtxLbls.Labels = lbls
	c.Assert(gotSecCtxLbl.ID, Equals, wantSecCtxLbls.ID)
	c.Assert(gotSecCtxLbl.Labels, DeepEquals, wantSecCtxLbls.Labels)
	c.Assert(gotSecCtxLbl.RefCount(), Equals, 2)

	gotSecCtxLbl, err = ds.d.GetLabels(common.FirstFreeID + 1)
	c.Assert(err, Equals, nil)
	wantSecCtxLbls.ID = common.FirstFreeID + 1
	wantSecCtxLbls.Labels = lbls2
	c.Assert(gotSecCtxLbl.ID, Equals, wantSecCtxLbls.ID)
	c.Assert(gotSecCtxLbl.Labels, DeepEquals, wantSecCtxLbls.Labels)
	c.Assert(gotSecCtxLbl.RefCount(), Equals, 2)

	err = ds.d.DeleteLabelsByUUID(common.FirstFreeID, "containerLabel1-2")
	c.Assert(err, Equals, nil)
	gotSecCtxLbl, err = ds.d.GetLabels(common.FirstFreeID)
	wantSecCtxLbls.ID = common.FirstFreeID
	wantSecCtxLbls.Labels = lbls
	c.Assert(gotSecCtxLbl.ID, Equals, wantSecCtxLbls.ID)
	c.Assert(gotSecCtxLbl.Labels, DeepEquals, wantSecCtxLbls.Labels)
	c.Assert(gotSecCtxLbl.RefCount(), Equals, 1)

	err = ds.d.DeleteLabelsByUUID(common.FirstFreeID, "containerLabel1-3")
	c.Assert(err, Equals, nil)
	gotSecCtxLbl, err = ds.d.GetLabels(common.FirstFreeID)
	c.Assert(err, Equals, nil)
	var emptySecCtxLblPtr *types.SecCtxLabel
	c.Assert(gotSecCtxLbl, Equals, emptySecCtxLblPtr)

	ds.d.setMaxID(common.FirstFreeID)
	c.Assert(err, Equals, nil)

	err = ds.d.DeleteLabelsByUUID(common.FirstFreeID, "containerLabel1-non-existent")
	c.Assert(err, Equals, nil)
	gotSecCtxLbl, err = ds.d.GetLabels(common.FirstFreeID)
	c.Assert(err, Equals, nil)
	c.Assert(gotSecCtxLbl, Equals, emptySecCtxLblPtr)

	secCtxLbl, new, err = ds.d.PutLabels(lbls2, "containerLabel2-3")
	c.Assert(err, Equals, nil)
	c.Assert(secCtxLbl.ID, Equals, common.FirstFreeID+1)
	c.Assert(secCtxLbl.RefCount(), Equals, 3)
	c.Assert(new, Equals, false)

	sha256sum, err := lbls2.SHA256Sum()
	c.Assert(err, Equals, nil)

	gotSecCtxLbl, err = ds.d.GetLabelsBySHA256(sha256sum)
	c.Assert(err, Equals, nil)
	c.Assert(gotSecCtxLbl, DeepEquals, secCtxLbl)

	err = ds.d.DeleteLabelsBySHA256(sha256sum, "containerLabel2-1")
	c.Assert(err, Equals, nil)
	err = ds.d.DeleteLabelsByUUID(common.FirstFreeID+1, "containerLabel2-2")
	c.Assert(err, Equals, nil)
	err = ds.d.DeleteLabelsByUUID(common.FirstFreeID+1, "containerLabel2-3")
	c.Assert(err, Equals, nil)

	secCtxLbl, new, err = ds.d.PutLabels(lbls2, "containerLabel2-3")
	c.Assert(err, Equals, nil)
	c.Assert(secCtxLbl.ID, Equals, common.FirstFreeID)
	c.Assert(secCtxLbl.RefCount(), Equals, 1)
	c.Assert(new, Equals, true)

	secCtxLbl, new, err = ds.d.PutLabels(lbls, "containerLabel2-3")
	c.Assert(err, Equals, nil)
	c.Assert(secCtxLbl.ID, Equals, common.FirstFreeID+1)
	c.Assert(secCtxLbl.RefCount(), Equals, 1)
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
