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

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/bpf/lbmap"
	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/bpf"
)

var (
	NonAvailable = errors.New("Method not available")
)

func bypassPutService(id int64, svc *models.Service) error {
	fe, err := types.NewL3n4AddrFromModel(svc.FrontendAddress)
	if err != nil {
		return err
	}

	frontend := types.L3n4AddrID{
		L3n4Addr: *fe,
		ID:       types.ServiceID(id),
	}

	backends := []types.L3n4Addr{}
	for _, v := range svc.BackendAddresses {
		if b, err := types.NewL3n4AddrFromBackendModel(v); err != nil {
			return err
		} else {
			backends = append(backends, *b)
		}
	}

	revnat := false
	if svc.Flags != nil {
		revnat = svc.Flags.DirectServerReturn
	}

	lbSvc := types.LBSVC{
		FE:  frontend,
		BES: backends,
	}
	svcKey, svcValues, err := lbmap.LBSVC2ServiceKeynValue(lbSvc)
	if err != nil {
		return err
	}

	return lbmap.AddSVC2BPFMap(svcKey, svcValues, revnat, int(frontend.ID))
}

func SVCDelete(feL3n4 types.L3n4Addr) error {
	return lbmap.DeleteService(lbmap.L3n4Addr2ServiceKey(feL3n4))
}

func SVCGet(feL3n4 types.L3n4Addr) (*types.LBSVC, error) {
	key := lbmap.L3n4Addr2ServiceKey(feL3n4)
	svc, err := lbmap.LookupService(key)
	if err != nil {
		return nil, err
	}
	besLen := 0
	if key.IsIPv6() {
		besLen = int(svc.(*lbmap.Service6Value).Count)
	} else {
		besLen = int(svc.(*lbmap.Service4Value).Count)
	}
	bes := []types.L3n4Addr{}
	svcID := types.ServiceID(0)
	for i := 1; i <= besLen; i++ {
		key.SetBackend(i)
		svc, err := lbmap.LookupService(key)
		if err != nil {
			return nil, err
		}
		sv, err := lbmap.ServiceValue2L3n4Addr(key, svc)
		if err != nil {
			return nil, err
		}
		bes = append(bes, *sv)
		if i == 1 {
			svcID = types.ServiceID(svc.RevNatKey().GetKey())
		}
	}
	return &types.LBSVC{
		FE: types.L3n4AddrID{
			ID:       svcID,
			L3n4Addr: feL3n4,
		},
		BES: bes,
	}, nil
}

func SVCDump() ([]types.LBSVC, error) {
	svcs := types.SVCMap{}

	parseSVCEntries := func(key bpf.MapKey, value bpf.MapValue) {
		svcKey := key.(lbmap.ServiceKey)
		//It's the frontend service so we don't add this one
		if svcKey.GetBackend() == 0 {
			return
		}
		svcValue := value.(lbmap.ServiceValue)
		fe, be, err := lbmap.ServiceKeynValue2FEnBE(svcKey, svcValue)
		if err != nil {
			log.Errorf("%s", err)
			return
		}
		svcs.AddFEnBE(fe, be, svcKey.GetBackend())
	}
	if err := lbmap.Service4Map.Dump(lbmap.Service4DumpParser, parseSVCEntries); err != nil {
		return nil, err
	}
	if err := lbmap.Service6Map.Dump(lbmap.Service6DumpParser, parseSVCEntries); err != nil {
		return nil, err
	}

	dump := []types.LBSVC{}
	for _, v := range svcs {
		dump = append(dump, v)
	}
	return dump, nil
}
