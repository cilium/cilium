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
	"encoding/json"
	"path"
	"strconv"
	"time"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/labels"
)

func (d *Daemon) updateSecLabelIDRef(secCtxLabels labels.SecCtxLabel) error {
	key := path.Join(common.LabelIDKeyPath, strconv.FormatUint(uint64(secCtxLabels.ID), 10))
	return d.kvClient.SetValue(key, secCtxLabels)
}

// gasNewSecLabelID gets and sets a New SecLabel ID.
func (d *Daemon) gasNewSecLabelID(secCtxLabel *labels.SecCtxLabel) error {
	baseID, err := d.GetMaxLabelID()
	if err != nil {
		return err
	}

	return d.kvClient.GASNewSecLabelID(common.LabelIDKeyPath, baseID, secCtxLabel)
}

// PutLabels stores to given labels in consul and returns the SecCtxLabels created for
// the given labels.
func (d *Daemon) PutLabels(lbls labels.Labels, contID string) (*labels.SecCtxLabel, bool, error) {
	log.Debugf("Resolving labels %+v of %s", lbls, contID)

	isNew := false

	// Retrieve unique SHA256Sum for labels
	sha256Sum, err := lbls.SHA256Sum()
	if err != nil {
		return nil, false, err
	}
	lblPath := path.Join(common.LabelsKeyPath, sha256Sum)

	// Lock that sha256Sum
	lockKey, err := d.kvClient.LockPath(lblPath)
	if err != nil {
		return nil, false, err
	}
	defer lockKey.Unlock()

	// After lock complete, get label's path
	rmsg, err := d.kvClient.GetValue(lblPath)
	if err != nil {
		return nil, false, err
	}

	secCtxLbls := labels.NewSecCtxLabel()
	if rmsg == nil {
		secCtxLbls.Labels = lbls
		isNew = true
	} else {
		if err := json.Unmarshal(rmsg, &secCtxLbls); err != nil {
			return nil, false, err
		}
		// If RefCount is 0 then we have to retrieve a new ID
		if secCtxLbls.RefCount() == 0 {
			isNew = true
			secCtxLbls.Containers = make(map[string]time.Time)
		}
	}

	secCtxLbls.AddOrUpdateContainer(contID)

	if isNew {
		if err := d.gasNewSecLabelID(secCtxLbls); err != nil {
			return nil, false, err
		}
	} else if err := d.updateSecLabelIDRef(*secCtxLbls); err != nil {
		return nil, false, err
	}

	log.Debugf("Incrementing label %d ref-count to %d\n", secCtxLbls.ID, secCtxLbls.RefCount())

	d.AddOrUpdateUINode(secCtxLbls.ID, secCtxLbls.Labels.ToSlice(), secCtxLbls.RefCount())

	err = d.kvClient.SetValue(lblPath, secCtxLbls)

	return secCtxLbls, isNew, err
}

// GetLabels returns the SecCtxLabels that belongs to the given id.
func (d *Daemon) GetLabels(id uint32) (*labels.SecCtxLabel, error) {
	if id > 0 && id < common.FirstFreeLabelID {
		key := labels.ReservedID(id).String()
		if key == "" {
			return nil, nil
		}

		lbl := labels.NewLabel(
			key, "", common.ReservedLabelSource,
		)
		secLbl := labels.NewSecCtxLabel()
		secLbl.AddOrUpdateContainer(lbl.String())
		secLbl.ID = id
		secLbl.Labels = labels.Labels{
			common.ReservedLabelSource: lbl,
		}

		return secLbl, nil
	}

	strID := strconv.FormatUint(uint64(id), 10)
	rmsg, err := d.kvClient.GetValue(path.Join(common.LabelIDKeyPath, strID))
	if err != nil {
		return nil, err
	}
	if rmsg == nil {
		return nil, nil
	}

	var secCtxLabels labels.SecCtxLabel
	if err := json.Unmarshal(rmsg, &secCtxLabels); err != nil {
		return nil, err
	}
	if secCtxLabels.RefCount() == 0 {
		return nil, nil
	}
	return &secCtxLabels, nil
}

// GetLabelsBySHA256 returns the SecCtxLabels that have the given SHA256SUM.
func (d *Daemon) GetLabelsBySHA256(sha256sum string) (*labels.SecCtxLabel, error) {
	path := path.Join(common.LabelsKeyPath, sha256sum)
	rmsg, err := d.kvClient.GetValue(path)
	if err != nil {
		return nil, err
	}
	if rmsg == nil {
		return nil, nil
	}
	var secCtxLabels labels.SecCtxLabel
	if err := json.Unmarshal(rmsg, &secCtxLabels); err != nil {
		return nil, err
	}
	if secCtxLabels.RefCount() == 0 {
		return nil, nil
	}
	return &secCtxLabels, nil
}

// DeleteLabelsByUUID deletes the SecCtxLabels belonging to the given id.
func (d *Daemon) DeleteLabelsByUUID(id uint32, contID string) error {
	secCtxLabels, err := d.GetLabels(id)
	if err != nil {
		return err
	}
	if secCtxLabels == nil {
		return nil
	}
	sha256sum, err := secCtxLabels.Labels.SHA256Sum()
	if err != nil {
		return err
	}

	return d.DeleteLabelsBySHA256(sha256sum, contID)
}

// DeleteLabelsBySHA256 deletes the SecCtxLabels that belong to the labels' sha256Sum.
func (d *Daemon) DeleteLabelsBySHA256(sha256Sum string, contID string) error {
	if sha256Sum == "" {
		return nil
	}
	lblPath := path.Join(common.LabelsKeyPath, sha256Sum)
	// Lock that sha256Sum
	lockKey, err := d.kvClient.LockPath(lblPath)
	if err != nil {
		return err
	}
	defer lockKey.Unlock()

	// After lock complete, get label's path
	rmsg, err := d.kvClient.GetValue(lblPath)
	if err != nil {
		return err
	}
	if rmsg == nil {
		return nil
	}

	var dbSecCtxLbls labels.SecCtxLabel
	if err := json.Unmarshal(rmsg, &dbSecCtxLbls); err != nil {
		return err
	}
	dbSecCtxLbls.DelContainer(contID)

	// update the value in the kvstore
	if err := d.updateSecLabelIDRef(dbSecCtxLbls); err != nil {
		return err
	}

	if dbSecCtxLbls.RefCount() == 0 {
		d.DeleteUINode(dbSecCtxLbls.ID)
	} else {
		d.AddOrUpdateUINode(dbSecCtxLbls.ID, dbSecCtxLbls.Labels.ToSlice(), dbSecCtxLbls.RefCount())
	}

	log.Debugf("Decremented label %d ref-count to %d\n", dbSecCtxLbls.ID, dbSecCtxLbls.RefCount())

	return d.kvClient.SetValue(lblPath, dbSecCtxLbls)
}

// GetMaxID returns the maximum possible free UUID stored in consul.
func (d *Daemon) GetMaxLabelID() (uint32, error) {
	return d.kvClient.GetMaxID(common.LastFreeLabelIDKeyPath, common.FirstFreeLabelID)
}
