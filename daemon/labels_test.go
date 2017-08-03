// Copyright 2016-2017 Authors of Cilium
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

package main

import (
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/daemon/options"
	"github.com/cilium/cilium/pkg/apierror"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"

	. "gopkg.in/check.v1"
)

var (
	lbls = labels.Labels{
		"foo":    labels.NewLabel("foo", "bar", labels.LabelSourceContainer),
		"foo2":   labels.NewLabel("foo2", "=bar2", labels.LabelSourceContainer),
		"key":    labels.NewLabel("key", "", labels.LabelSourceContainer),
		"foo==":  labels.NewLabel("foo==", "==", labels.LabelSourceContainer),
		`foo\\=`: labels.NewLabel(`foo\\=`, `\=`, labels.LabelSourceContainer),
		`//=/`:   labels.NewLabel(`//=/`, "", labels.LabelSourceContainer),
		`%`:      labels.NewLabel(`%`, `%ed`, labels.LabelSourceContainer),
	}
	lbls2 = labels.Labels{
		"foo":  labels.NewLabel("foo", "bar", labels.LabelSourceContainer),
		"foo2": labels.NewLabel("foo2", "=bar2", labels.LabelSourceContainer),
	}
	wantSecCtxLbls = policy.Identity{
		ID: 123,
		Endpoints: map[string]time.Time{
			"cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307": time.Now().UTC(),
		},
		Labels: lbls,
	}
	nilAPIError *apierror.APIError
)

func (ds *DaemonSuite) SetUpTest(c *C) {
	time.Local = time.UTC
	tempRunDir, err := ioutil.TempDir("", "cilium-test-run")
	c.Assert(err, IsNil)
	err = os.Mkdir(filepath.Join(tempRunDir, "globals"), 0777)
	c.Assert(err, IsNil)

	daemonConf := &Config{
		DryMode: true,
		Opts:    option.NewBoolOptions(&options.Library),
	}
	daemonConf.RunDir = tempRunDir
	daemonConf.StateDir = tempRunDir
	daemonConf.DockerEndpoint = "tcp://127.0.0.1"
	daemonConf.ValidLabelPrefixes = nil
	daemonConf.Opts.Set(endpoint.OptionDropNotify, true)

	err = kvstore.SetupDummy()
	c.Assert(err, IsNil)

	d, err := NewDaemon(daemonConf)
	c.Assert(err, IsNil)
	ds.d = d
	kvstore.Client.DeleteTree(common.OperationalPath)
	// Needs to be less than 1 second otherwise GetCachedMaxLabelID might
	// not work properly
	d.EnableKVStoreWatcher(time.Nanosecond)
}

func (ds *DaemonSuite) TearDownTest(c *C) {
	os.RemoveAll(ds.d.conf.RunDir)
}

func (ds *DaemonSuite) TestLabels(c *C) {
	//Set up last free ID with zero
	id, err := GetMaxLabelID()
	c.Assert(err, IsNil)
	c.Assert(id, Equals, policy.MinimalNumericIdentity)

	secCtxLbl, new, err := ds.d.CreateOrUpdateIdentity(lbls, "containerLabel1-1")
	c.Assert(err, IsNil)
	c.Assert(secCtxLbl.ID, Equals, policy.MinimalNumericIdentity)
	c.Assert(secCtxLbl.RefCount(), Equals, 1)
	c.Assert(new, Equals, true)

	secCtxLbl, new, err = ds.d.CreateOrUpdateIdentity(lbls, "containerLabel1-2")
	c.Assert(err, IsNil)
	c.Assert(secCtxLbl.ID, Equals, policy.MinimalNumericIdentity)
	c.Assert(secCtxLbl.RefCount(), Equals, 2)
	c.Assert(new, Equals, false)

	secCtxLbl, new, err = ds.d.CreateOrUpdateIdentity(lbls2, "containerLabel2-1")
	c.Assert(err, IsNil)
	c.Assert(secCtxLbl.ID, Equals, policy.MinimalNumericIdentity+1)
	c.Assert(secCtxLbl.RefCount(), Equals, 1)
	c.Assert(new, Equals, true)

	secCtxLbl, new, err = ds.d.CreateOrUpdateIdentity(lbls2, "containerLabel2-2")
	c.Assert(err, IsNil)
	c.Assert(secCtxLbl.ID, Equals, policy.MinimalNumericIdentity+1)
	c.Assert(secCtxLbl.RefCount(), Equals, 2)
	c.Assert(new, Equals, false)

	secCtxLbl, new, err = ds.d.CreateOrUpdateIdentity(lbls, "containerLabel1-3")
	c.Assert(err, IsNil)
	c.Assert(secCtxLbl.ID, Equals, policy.MinimalNumericIdentity)
	c.Assert(secCtxLbl.RefCount(), Equals, 3)
	c.Assert(new, Equals, false)

	//Get labels from ID
	gotSecCtxLbl, err := ds.d.LookupIdentity(policy.MinimalNumericIdentity)
	c.Assert(err, IsNil)
	wantSecCtxLbls.ID = policy.MinimalNumericIdentity
	wantSecCtxLbls.Labels = lbls
	c.Assert(gotSecCtxLbl.ID, Equals, wantSecCtxLbls.ID)
	c.Assert(gotSecCtxLbl.Labels, DeepEquals, wantSecCtxLbls.Labels)
	c.Assert(gotSecCtxLbl.RefCount(), Equals, 3)

	err = ds.d.DeleteIdentity(policy.MinimalNumericIdentity, "containerLabel1-1")
	c.Assert(err, IsNil)
	gotSecCtxLbl, err = ds.d.LookupIdentity(policy.MinimalNumericIdentity)
	c.Assert(err, IsNil)
	wantSecCtxLbls.ID = policy.MinimalNumericIdentity
	wantSecCtxLbls.Labels = lbls
	c.Assert(gotSecCtxLbl.ID, Equals, wantSecCtxLbls.ID)
	c.Assert(gotSecCtxLbl.Labels, DeepEquals, wantSecCtxLbls.Labels)
	c.Assert(gotSecCtxLbl.RefCount(), Equals, 2)

	gotSecCtxLbl, err = ds.d.LookupIdentity(policy.MinimalNumericIdentity + 1)
	c.Assert(err, IsNil)
	wantSecCtxLbls.ID = policy.MinimalNumericIdentity + 1
	wantSecCtxLbls.Labels = lbls2
	c.Assert(gotSecCtxLbl.ID, Equals, wantSecCtxLbls.ID)
	c.Assert(gotSecCtxLbl.Labels, DeepEquals, wantSecCtxLbls.Labels)
	c.Assert(gotSecCtxLbl.RefCount(), Equals, 2)

	err = ds.d.DeleteIdentity(policy.MinimalNumericIdentity, "containerLabel1-2")
	c.Assert(err, IsNil)
	gotSecCtxLbl, err = ds.d.LookupIdentity(policy.MinimalNumericIdentity)
	c.Assert(err, IsNil)
	wantSecCtxLbls.ID = policy.MinimalNumericIdentity
	wantSecCtxLbls.Labels = lbls
	c.Assert(gotSecCtxLbl.ID, Equals, wantSecCtxLbls.ID)
	c.Assert(gotSecCtxLbl.Labels, DeepEquals, wantSecCtxLbls.Labels)
	c.Assert(gotSecCtxLbl.RefCount(), Equals, 1)

	err = ds.d.DeleteIdentity(policy.MinimalNumericIdentity, "containerLabel1-3")
	c.Assert(err, IsNil)
	gotSecCtxLbl, err = ds.d.LookupIdentity(policy.MinimalNumericIdentity)
	c.Assert(err, IsNil)
	var emptySecCtxLblPtr *policy.Identity
	c.Assert(gotSecCtxLbl, Equals, emptySecCtxLblPtr)

	err = kvstore.Client.SetMaxID(common.LastFreeLabelIDKeyPath, policy.MinimalNumericIdentity.Uint32(), policy.MinimalNumericIdentity.Uint32())
	c.Assert(err, IsNil)

	err = ds.d.DeleteIdentity(policy.MinimalNumericIdentity, "containerLabel1-non-existent")
	c.Assert(err, DeepEquals, errors.New("identity not found"))
	gotSecCtxLbl, err = ds.d.LookupIdentity(policy.MinimalNumericIdentity)
	c.Assert(err, IsNil)
	c.Assert(gotSecCtxLbl, Equals, emptySecCtxLblPtr)

	secCtxLbl, new, err = ds.d.CreateOrUpdateIdentity(lbls2, "containerLabel2-3")
	c.Assert(err, IsNil)
	c.Assert(secCtxLbl.ID, Equals, policy.MinimalNumericIdentity+1)
	c.Assert(secCtxLbl.RefCount(), Equals, 3)
	c.Assert(new, Equals, false)

	sha256sum := lbls2.SHA256Sum()
	gotSecCtxLbl, err = LookupIdentityBySHA256(sha256sum)
	c.Assert(err, IsNil)
	c.Assert(gotSecCtxLbl, DeepEquals, secCtxLbl)

	err = ds.d.DeleteIdentityBySHA256(sha256sum, "containerLabel2-1")
	c.Assert(err, IsNil)
	err = ds.d.DeleteIdentity(policy.MinimalNumericIdentity+1, "containerLabel2-2")
	c.Assert(err, IsNil)
	err = ds.d.DeleteIdentity(policy.MinimalNumericIdentity+1, "containerLabel2-3")
	c.Assert(err, IsNil)

	secCtxLbl, new, err = ds.d.CreateOrUpdateIdentity(lbls2, "containerLabel2-3")
	c.Assert(err, IsNil)
	c.Assert(secCtxLbl.ID, Equals, policy.MinimalNumericIdentity)
	c.Assert(secCtxLbl.RefCount(), Equals, 1)
	c.Assert(new, Equals, true)

	secCtxLbl, new, err = ds.d.CreateOrUpdateIdentity(lbls, "containerLabel2-3")
	c.Assert(err, IsNil)
	c.Assert(secCtxLbl.ID, Equals, policy.MinimalNumericIdentity+1)
	c.Assert(secCtxLbl.RefCount(), Equals, 1)
	c.Assert(new, Equals, true)
}

func (ds *DaemonSuite) TestGetMaxID(c *C) {
	lastID := policy.NumericIdentity(common.MaxSetOfLabels - 1)
	err := kvstore.Client.SetValue(common.LastFreeLabelIDKeyPath, lastID)
	c.Assert(err, IsNil)

	id, err := GetMaxLabelID()
	c.Assert(err, IsNil)
	c.Assert(id, Equals, lastID)
}
