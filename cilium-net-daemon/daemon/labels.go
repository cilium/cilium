package daemon

import (
	"encoding/json"
	"errors"
	"strconv"

	"github.com/noironetworks/cilium-net/common"
	"github.com/noironetworks/cilium-net/common/types"

	"github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/hashicorp/consul/api"
)

func (d Daemon) getNextValidUUID() (int, error) {
	var lastID int
	valid := false
	for !valid {
		k, q, err := d.consul.KV().Get(common.LastFreeIDKeyPath, nil)
		if err != nil {
			return -1, err
		}

		// TODO do a proper checker to validate common.LastFreeIDKeyPath, when we start
		// from scratch the common.LastFreeIDKeyPath won't have any value stored.
		if k != nil {
			if err := json.Unmarshal(k.Value, &lastID); err != nil {
				return -1, err
			}
		} else {
			lastID = 1
		}

		log.Info("Acquiring next available UUID %d", lastID)
		nextID := lastID + 1
		if nextID > common.MaxSetOfLabels {
			return -1, errors.New("Reached maximum number free labels sets.")
		}
		lastIDByte, err := json.Marshal(nextID)
		if err != nil {
			return -1, err
		}

		// TODO do a proper checker to validate common.LastFreeIDKeyPath, when we start
		// from scratch the common.LastFreeIDKeyPath won't have any value stored.
		if k != nil {
			p := &api.KVPair{Key: common.LastFreeIDKeyPath, Value: lastIDByte, ModifyIndex: q.LastIndex}
			valid, _, err = d.consul.KV().CAS(p, nil)
		} else {
			p := &api.KVPair{Key: common.LastFreeIDKeyPath, Value: lastIDByte}
			_, err = d.consul.KV().Put(p, nil)
			valid = true
		}
		if err != nil {
			return -1, err
		}
	}
	log.Info("UUID %d acquired with success", lastID)
	return lastID, nil
}

func (d Daemon) GetLabelsID(labels types.Labels) (int, error) {
	// TODO fix race condition if the same sets of labels tries to retrieve an ID at
	// the same time
	sha256Sum, err := labels.SHA256Sum()
	if err != nil {
		return -1, err
	}

	lblsByte, err := json.Marshal(labels)
	if err != nil {
		return -1, err
	}

	//check if exists
	if kvPair, _, err := d.consul.KV().Get(common.LabelsKeyPath+sha256Sum, nil); err != nil {
		return -1, err
	} else {
		if kvPair != nil {
			var id int
			if err := json.Unmarshal(kvPair.Value, &id); err != nil {
				return -1, err
			}
			return id, nil
		}
	}

	id, err := d.getNextValidUUID()
	if err != nil {
		return -1, err
	}

	// TODO: Create some cleanup if failure
	strID := strconv.Itoa(id)
	p := &api.KVPair{Key: common.LabelsKeyPath + sha256Sum, Value: []byte(strID)}
	if _, err = d.consul.KV().Put(p, nil); err != nil {
		return -1, err
	}

	p = &api.KVPair{Key: common.IDKeyPath + strID, Value: lblsByte}
	if _, err = d.consul.KV().Put(p, nil); err != nil {
		return -1, err
	}

	d.TriggerPolicyUpdates([]int{id})

	return id, nil
}

func (d Daemon) GetLabels(id int) (*types.Labels, error) {
	strID := strconv.Itoa(id)
	pair, _, err := d.consul.KV().Get(common.IDKeyPath+strID, nil)
	if err != nil {
		return nil, err
	}
	if pair == nil {
		return nil, nil
	}
	var labels types.Labels
	if err := json.Unmarshal(pair.Value, &labels); err != nil {
		return nil, err
	}
	return &labels, nil
}

func (d Daemon) GetMaxID() (int, error) {
	var lastID int
	k, _, err := d.consul.KV().Get(common.LastFreeIDKeyPath, nil)
	if err != nil {
		return -1, err
	}
	if k == nil {
		return -1, errors.New("Last ID is unset")
	}
	if err := json.Unmarshal(k.Value, &lastID); err != nil {
		return -1, err
	}

	return lastID, nil
}
