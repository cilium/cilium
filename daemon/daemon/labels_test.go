//
// Copyright 2016 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
package daemon

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/common/types"

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
	tempLibDir, err := ioutil.TempDir("", "cilium-test")
	c.Assert(err, IsNil)
	tempRunDir, err := ioutil.TempDir("", "cilium-test-run")
	c.Assert(err, IsNil)
	err = os.Mkdir(filepath.Join(tempRunDir, "globals"), 0777)
	c.Assert(err, IsNil)

	nodeAddress, err := addressing.NewNodeAddress("beef:beef:beef:beef:aaaa:aaaa:1111:0", "10.1.0.1", "")
	c.Assert(err, IsNil)

	daemonConf := &Config{
		DryMode: true,
		Opts:    types.NewBoolOptions(&DaemonOptionLibrary),
	}
	daemonConf.LibDir = tempLibDir
	daemonConf.RunDir = tempRunDir
	daemonConf.LXCMap = nil
	daemonConf.NodeAddress = nodeAddress
	daemonConf.DockerEndpoint = "tcp://127.0.0.1"
	daemonConf.K8sEndpoint = "tcp://127.0.0.1"
	daemonConf.ValidLabelPrefixes = nil
	daemonConf.OptsMU.Lock()
	daemonConf.Opts.Set(types.OptionDropNotify, true)
	daemonConf.OptsMU.Unlock()
	daemonConf.Device = "undefined"

	err = daemonConf.SetKVBackend()
	c.Assert(err, IsNil)

	d1 := []byte("#!/usr/bin/env bash\necho \"OK\"\n")
	err = ioutil.WriteFile(filepath.Join(daemonConf.LibDir, "join_ep.sh"), d1, 0755)
	c.Assert(err, IsNil)
	err = ioutil.WriteFile(filepath.Join(daemonConf.LibDir, "init.sh"), d1, 0755)
	c.Assert(err, IsNil)

	d, err := NewDaemon(daemonConf)
	c.Assert(err, Equals, nil)
	ds.d = d
	d.kvClient.DeleteTree(common.OperationalPath)
}

func (ds *DaemonSuite) TearDownTest(c *C) {
	os.RemoveAll(ds.d.conf.LibDir)
	os.RemoveAll(ds.d.conf.RunDir)
}

func (ds *DaemonSuite) TestLabels(c *C) {
	//Set up last free ID with zero
	id, err := ds.d.GetMaxLabelID()
	c.Assert(err, Equals, nil)
	c.Assert(id, Equals, common.FirstFreeLabelID)

	secCtxLbl, new, err := ds.d.PutLabels(lbls, "containerLabel1-1")
	c.Assert(err, Equals, nil)
	c.Assert(secCtxLbl.ID, Equals, common.FirstFreeLabelID)
	c.Assert(secCtxLbl.RefCount(), Equals, 1)
	c.Assert(new, Equals, true)

	secCtxLbl, new, err = ds.d.PutLabels(lbls, "containerLabel1-2")
	c.Assert(err, Equals, nil)
	c.Assert(secCtxLbl.ID, Equals, common.FirstFreeLabelID)
	c.Assert(secCtxLbl.RefCount(), Equals, 2)
	c.Assert(new, Equals, false)

	secCtxLbl, new, err = ds.d.PutLabels(lbls2, "containerLabel2-1")
	c.Assert(err, Equals, nil)
	c.Assert(secCtxLbl.ID, Equals, common.FirstFreeLabelID+1)
	c.Assert(secCtxLbl.RefCount(), Equals, 1)
	c.Assert(new, Equals, true)

	secCtxLbl, new, err = ds.d.PutLabels(lbls2, "containerLabel2-2")
	c.Assert(err, Equals, nil)
	c.Assert(secCtxLbl.ID, Equals, common.FirstFreeLabelID+1)
	c.Assert(secCtxLbl.RefCount(), Equals, 2)
	c.Assert(new, Equals, false)

	secCtxLbl, new, err = ds.d.PutLabels(lbls, "containerLabel1-3")
	c.Assert(err, Equals, nil)
	c.Assert(secCtxLbl.ID, Equals, common.FirstFreeLabelID)
	c.Assert(secCtxLbl.RefCount(), Equals, 3)
	c.Assert(new, Equals, false)

	//Get labels from ID
	gotSecCtxLbl, err := ds.d.GetLabels(common.FirstFreeLabelID)
	c.Assert(err, Equals, nil)
	wantSecCtxLbls.ID = common.FirstFreeLabelID
	wantSecCtxLbls.Labels = lbls
	c.Assert(gotSecCtxLbl.ID, Equals, wantSecCtxLbls.ID)
	c.Assert(gotSecCtxLbl.Labels, DeepEquals, wantSecCtxLbls.Labels)
	c.Assert(gotSecCtxLbl.RefCount(), Equals, 3)

	err = ds.d.DeleteLabelsByUUID(common.FirstFreeLabelID, "containerLabel1-1")
	c.Assert(err, Equals, nil)
	gotSecCtxLbl, err = ds.d.GetLabels(common.FirstFreeLabelID)
	c.Assert(err, Equals, nil)
	wantSecCtxLbls.ID = common.FirstFreeLabelID
	wantSecCtxLbls.Labels = lbls
	c.Assert(gotSecCtxLbl.ID, Equals, wantSecCtxLbls.ID)
	c.Assert(gotSecCtxLbl.Labels, DeepEquals, wantSecCtxLbls.Labels)
	c.Assert(gotSecCtxLbl.RefCount(), Equals, 2)

	gotSecCtxLbl, err = ds.d.GetLabels(common.FirstFreeLabelID + 1)
	c.Assert(err, Equals, nil)
	wantSecCtxLbls.ID = common.FirstFreeLabelID + 1
	wantSecCtxLbls.Labels = lbls2
	c.Assert(gotSecCtxLbl.ID, Equals, wantSecCtxLbls.ID)
	c.Assert(gotSecCtxLbl.Labels, DeepEquals, wantSecCtxLbls.Labels)
	c.Assert(gotSecCtxLbl.RefCount(), Equals, 2)

	err = ds.d.DeleteLabelsByUUID(common.FirstFreeLabelID, "containerLabel1-2")
	c.Assert(err, Equals, nil)
	gotSecCtxLbl, err = ds.d.GetLabels(common.FirstFreeLabelID)
	wantSecCtxLbls.ID = common.FirstFreeLabelID
	wantSecCtxLbls.Labels = lbls
	c.Assert(gotSecCtxLbl.ID, Equals, wantSecCtxLbls.ID)
	c.Assert(gotSecCtxLbl.Labels, DeepEquals, wantSecCtxLbls.Labels)
	c.Assert(gotSecCtxLbl.RefCount(), Equals, 1)

	err = ds.d.DeleteLabelsByUUID(common.FirstFreeLabelID, "containerLabel1-3")
	c.Assert(err, Equals, nil)
	gotSecCtxLbl, err = ds.d.GetLabels(common.FirstFreeLabelID)
	c.Assert(err, Equals, nil)
	var emptySecCtxLblPtr *types.SecCtxLabel
	c.Assert(gotSecCtxLbl, Equals, emptySecCtxLblPtr)

	err = ds.d.kvClient.SetMaxID(common.LastFreeLabelIDKeyPath, common.FirstFreeLabelID, common.FirstFreeLabelID)
	c.Assert(err, Equals, nil)

	err = ds.d.DeleteLabelsByUUID(common.FirstFreeLabelID, "containerLabel1-non-existent")
	c.Assert(err, Equals, nil)
	gotSecCtxLbl, err = ds.d.GetLabels(common.FirstFreeLabelID)
	c.Assert(err, Equals, nil)
	c.Assert(gotSecCtxLbl, Equals, emptySecCtxLblPtr)

	secCtxLbl, new, err = ds.d.PutLabels(lbls2, "containerLabel2-3")
	c.Assert(err, Equals, nil)
	c.Assert(secCtxLbl.ID, Equals, common.FirstFreeLabelID+1)
	c.Assert(secCtxLbl.RefCount(), Equals, 3)
	c.Assert(new, Equals, false)

	sha256sum, err := lbls2.SHA256Sum()
	c.Assert(err, Equals, nil)

	gotSecCtxLbl, err = ds.d.GetLabelsBySHA256(sha256sum)
	c.Assert(err, Equals, nil)
	c.Assert(gotSecCtxLbl, DeepEquals, secCtxLbl)

	err = ds.d.DeleteLabelsBySHA256(sha256sum, "containerLabel2-1")
	c.Assert(err, Equals, nil)
	err = ds.d.DeleteLabelsByUUID(common.FirstFreeLabelID+1, "containerLabel2-2")
	c.Assert(err, Equals, nil)
	err = ds.d.DeleteLabelsByUUID(common.FirstFreeLabelID+1, "containerLabel2-3")
	c.Assert(err, Equals, nil)

	secCtxLbl, new, err = ds.d.PutLabels(lbls2, "containerLabel2-3")
	c.Assert(err, Equals, nil)
	c.Assert(secCtxLbl.ID, Equals, common.FirstFreeLabelID)
	c.Assert(secCtxLbl.RefCount(), Equals, 1)
	c.Assert(new, Equals, true)

	secCtxLbl, new, err = ds.d.PutLabels(lbls, "containerLabel2-3")
	c.Assert(err, Equals, nil)
	c.Assert(secCtxLbl.ID, Equals, common.FirstFreeLabelID+1)
	c.Assert(secCtxLbl.RefCount(), Equals, 1)
	c.Assert(new, Equals, true)
}

func (ds *DaemonSuite) TestGetMaxID(c *C) {
	lastID := uint32(common.MaxSetOfLabels - 1)
	err := ds.d.kvClient.SetValue(common.LastFreeLabelIDKeyPath, lastID)
	c.Assert(err, Equals, nil)

	id, err := ds.d.GetMaxLabelID()
	c.Assert(err, Equals, nil)
	c.Assert(id, Equals, (common.MaxSetOfLabels - 1))
}
