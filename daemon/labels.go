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
	"encoding/json"
	"fmt"
	"path"
	"strconv"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/policy"
	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/apierror"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logfields"
	"github.com/cilium/cilium/pkg/nodeaddress"
	"github.com/cilium/cilium/pkg/policy"

	"github.com/go-openapi/runtime/middleware"
	log "github.com/sirupsen/logrus"
)

func updateSecLabelIDRef(id policy.Identity) error {
	key := path.Join(common.LabelIDKeyPath, strconv.FormatUint(uint64(id.ID), 10))
	return kvstore.Client().SetValue(key, id)
}

// gasNewSecLabelID gets and sets a New SecLabel ID.
func gasNewSecLabelID(id *policy.Identity) error {
	baseID, err := GetMaxLabelID()
	if err != nil {
		return err
	}

	return kvstore.Client().GASNewSecLabelID(common.LabelIDKeyPath, uint32(baseID), id)
}

func (d *Daemon) CreateOrUpdateIdentity(lbls labels.Labels, epid string) (*policy.Identity, bool, error) {
	clusterEndpointID := nodeaddress.GetExternalIPv4().String() + ":" + epid

	log.WithFields(log.Fields{
		logfields.EndpointID:     epid,
		logfields.IdentityLabels: lbls.String(),
	}).Debug("Associating endpoint with identity")

	isNew := false

	// Calculate hash over identity labels and generate path
	identityPath := path.Join(common.LabelsKeyPath, lbls.SHA256Sum())

	// Lock the identity
	lockKey, err := kvstore.LockPath(identityPath)
	if err != nil {
		return nil, false, err
	}
	defer lockKey.Unlock()

	// Retrieve current identity for labels
	rmsg, err := kvstore.Client().GetValue(identityPath)
	if err != nil {
		return nil, false, err
	}

	identity := policy.NewIdentity()

	if rmsg == nil {
		// Identity does not exist yet, create new one
		identity.Labels = lbls
		isNew = true
	} else {
		if err := json.Unmarshal(rmsg, &identity); err != nil {
			return nil, false, err
		}

		// If RefCount is 0 then we have to retrieve a new ID
		if identity.RefCount() == 0 {
			isNew = true
			identity.Endpoints = make(map[string]time.Time)
		}
	}

	// Refresh timestamp of endpoint association
	identity.AssociateEndpoint(clusterEndpointID)

	// FIXME FIXME FIXME
	//
	// These operations are currently not atomic. Use transactional
	// K/V store operations

	if isNew {
		log.WithFields(log.Fields{
			logfields.EndpointID:     epid,
			logfields.IdentityLabels: lbls.String(),
		}).Debug("Creating new identity")

		if err := gasNewSecLabelID(identity); err != nil {
			return nil, false, err
		}
	} else {
		log.WithFields(log.Fields{
			logfields.EndpointID:     epid,
			logfields.Identity:       identity.StringID(),
			logfields.IdentityLabels: lbls.String(),
			"refCount":               identity.RefCount(),
		}).Debug("Keeping identity alive")

		if err := updateSecLabelIDRef(*identity); err != nil {
			return nil, false, err
		}
	}

	// store updated identity entry
	if err = kvstore.Client().SetValue(identityPath, identity); err != nil {
		return nil, false, err
	}

	return identity, isNew, nil
}

func (d *Daemon) updateEndpointIdentity(epID, oldLabelsHash string, opLabels *labels.OpLabels) (*policy.Identity, string, error) {
	lbls := opLabels.IdentityLabels()

	log.WithFields(log.Fields{
		logfields.EndpointID:     epID,
		logfields.IdentityLabels: lbls,
	}).Debug("Resolving identity for endpoint")

	newLabelsHash := lbls.SHA256Sum()
	identity, _, err := d.CreateOrUpdateIdentity(lbls, epID)
	if err != nil {
		return nil, "", fmt.Errorf("unable to get identity ID: %s", err)
	}

	if newLabelsHash != oldLabelsHash {
		if err := d.DeleteIdentityBySHA256(oldLabelsHash, epID); err != nil {
			log.WithFields(log.Fields{
				"oldIdentityHash":    oldLabelsHash,
				logfields.EndpointID: epID,
			}).WithError(err).Warn("Unable to delete old identity of endpoint")
		}
	}

	log.WithFields(log.Fields{
		logfields.EndpointID:     epID,
		logfields.IdentityLabels: lbls,
		logfields.Identity:       identity.StringID(),
	}).Debug("Resolved identity for endpoint")

	return identity, newLabelsHash, nil
}

func parseIdentityResponse(rmsg []byte) (*policy.Identity, error) {
	var id policy.Identity

	// Empty reply
	if rmsg == nil {
		return nil, nil
	}

	if err := json.Unmarshal(rmsg, &id); err != nil {
		return nil, apierror.Error(GetIdentityInvalidStorageFormatCode, err)
	}

	// Unused identity (EOL)
	if id.RefCount() == 0 {
		return nil, nil
	}

	return &id, nil
}

func (d *Daemon) LookupIdentity(id policy.NumericIdentity) (*policy.Identity, error) {
	if id > 0 && id < policy.MinimalNumericIdentity {
		key := id.String()
		lbl := labels.NewLabel(
			key, "", labels.LabelSourceReserved,
		)
		secLbl := policy.NewIdentity()
		secLbl.AssociateEndpoint(lbl.String())
		secLbl.ID = id
		secLbl.Labels = labels.Labels{
			key: lbl,
		}

		return secLbl, nil
	}

	strID := strconv.FormatUint(uint64(id), 10)
	rmsg, err := kvstore.Client().GetValue(path.Join(common.LabelIDKeyPath, strID))
	if err != nil {
		return nil, apierror.Error(GetIdentityUnreachableCode, err)
	}

	return parseIdentityResponse(rmsg)
}

func LookupIdentityBySHA256(sha256sum string) (*policy.Identity, error) {
	rmsg, err := kvstore.Client().GetValue(path.Join(common.LabelsKeyPath, sha256sum))
	if err != nil {
		return nil, apierror.Error(GetIdentityUnreachableCode, err)
	}

	return parseIdentityResponse(rmsg)
}

type getIdentity struct {
	daemon *Daemon
}

func NewGetIdentityHandler(d *Daemon) GetIdentityHandler {
	return &getIdentity{daemon: d}
}

func (h *getIdentity) Handle(params GetIdentityParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /identity request")

	identities := []*models.Identity{}
	if params.Labels == nil {
		// if labels is nil, return all identities from the kvstore
		// This is in response to "identity list" command
		outputList, err := kvstore.Client().ListPrefix(common.LabelIDKeyPath)
		if err != nil {
			return apierror.Error(GetIdentityIDInvalidStorageFormatCode, err)
		}
		for _, v := range outputList {
			if id, err := parseIdentityResponse(v); err != nil {
				return apierror.Error(GetIdentityIDInvalidStorageFormatCode, err)
			} else if id != nil {
				identities = append(identities, id.GetModel())
			}
		}
	} else {
		lbls := labels.NewLabelsFromModel(params.Labels)
		if id, err := LookupIdentityBySHA256(lbls.SHA256Sum()); err != nil {
			if apierr, ok := err.(*apierror.APIError); ok {
				return apierr
			}
			return apierror.Error(GetIdentityUnreachableCode, err)
		} else if id != nil {
			identities = append(identities, id.GetModel())
		}
	}
	return NewGetIdentityOK().WithPayload(identities)
}

type getIdentityID struct {
	daemon *Daemon
}

func NewGetIdentityIDHandler(d *Daemon) GetIdentityIDHandler {
	return &getIdentityID{daemon: d}
}

func (h *getIdentityID) Handle(params GetIdentityIDParams) middleware.Responder {
	d := h.daemon

	nid, err := policy.ParseNumericIdentity(params.ID)
	if err != nil {
		return NewGetIdentityIDBadRequest()
	}

	if id, err := d.LookupIdentity(nid); err != nil {
		if apierr, ok := err.(*apierror.APIError); ok {
			return apierr
		}
		return apierror.Error(GetIdentityUnreachableCode, err)
	} else if id == nil {
		return NewGetIdentityIDNotFound()
	} else {
		id.LabelsSHA256 = id.Labels.SHA256Sum()
		return NewGetIdentityIDOK().WithPayload(id.GetModel())
	}
}

// DeleteIdentity deletes identity
func (d *Daemon) DeleteIdentity(id policy.NumericIdentity, epid string) error {
	if id, err := d.LookupIdentity(id); err != nil {
		return err
	} else if id == nil {
		return fmt.Errorf("identity not found")
	} else {
		hash := id.Labels.SHA256Sum()
		if err := d.DeleteIdentityBySHA256(hash, epid); err != nil {
			return err
		}
	}

	return nil
}

// DeleteIdentityBySHA256 deletes the SecCtxLabels that belong to the labels' sha256Sum.
func (d *Daemon) DeleteIdentityBySHA256(sha256Sum string, epid string) error {
	if epid != "" {
		epid = nodeaddress.GetExternalIPv4().String() + ":" + epid
	}

	if sha256Sum == "" {
		return nil
	}
	lblPath := path.Join(common.LabelsKeyPath, sha256Sum)
	// Lock that sha256Sum
	lockKey, err := kvstore.LockPath(lblPath)
	if err != nil {
		return err
	}
	defer lockKey.Unlock()

	// After lock complete, get label's path
	rmsg, err := kvstore.Client().GetValue(lblPath)
	if err != nil {
		return err
	}
	if rmsg == nil {
		return fmt.Errorf("label patch not found")
	}

	var dbSecCtxLbls policy.Identity
	if err := json.Unmarshal(rmsg, &dbSecCtxLbls); err != nil {
		return err
	}

	if epid != "" && !dbSecCtxLbls.DisassociateEndpoint(epid) {
		return fmt.Errorf("Association not found")
	}

	// FIXME FIXME FIXME
	//
	// These operations are currently not atomic. Use transactional
	// K/V store operations

	// update the value in the kvstore
	if err := updateSecLabelIDRef(dbSecCtxLbls); err != nil {
		return err
	}

	log.WithFields(log.Fields{
		logfields.EndpointID:     epid,
		logfields.IdentityLabels: dbSecCtxLbls.ID,
		"count":                  dbSecCtxLbls.RefCount(),
	}).Debug("Decremented label ref-count")

	return kvstore.Client().SetValue(lblPath, dbSecCtxLbls)
}

// GetMaxLabelID returns the maximum possible free UUID stored in consul.
func GetMaxLabelID() (policy.NumericIdentity, error) {
	n, err := kvstore.Client().GetMaxID(common.LastFreeLabelIDKeyPath, policy.MinimalNumericIdentity.Uint32())
	return policy.NumericIdentity(n), err
}
