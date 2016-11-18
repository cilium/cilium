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
package lb

import (
	"errors"

	"github.com/cilium/cilium/bpf/lbmap"
	"github.com/cilium/cilium/common/bpf"
	"github.com/cilium/cilium/common/types"
)

var (
	NonAvailable = errors.New("Method not available")
)

type LBClient struct{}

func NewLBClient() *LBClient {
	return &LBClient{}
}

func (cli *LBClient) SVCAdd(fe types.L3n4AddrID, be []types.L3n4Addr, addRevNAT bool) error {
	svc := types.LBSVC{
		FE:  fe,
		BES: be,
	}
	svcKey, svcValues, err := lbmap.LBSVC2ServiceKeynValue(svc)
	if err != nil {
		return err
	}
	return lbmap.AddSVC2BPFMap(svcKey, svcValues, addRevNAT, int(fe.ID))
}

func (cli *LBClient) SVCDelete(feL3n4 types.L3n4Addr) error {
	return lbmap.DeleteService(lbmap.L3n4Addr2ServiceKey(feL3n4))
}

func (cli *LBClient) SVCDeleteBySHA256Sum(_ string) error {
	return NonAvailable
}

func (cli *LBClient) SVCDeleteAll() error {
	if err := lbmap.Service6Map.DeleteAll(); err != nil {
		log.Warningf("%s", err)
	}
	if err := lbmap.Service4Map.DeleteAll(); err != nil {
		log.Warningf("%s", err)
	}
	return nil
}

func (cli *LBClient) SVCGet(feL3n4 types.L3n4Addr) (*types.LBSVC, error) {
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

func (cli *LBClient) SVCGetBySHA256Sum(_ string) (*types.LBSVC, error) {
	return nil, NonAvailable
}

func (cli *LBClient) SVCDump() ([]types.LBSVC, error) {
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
		if err := svcs.AddFEnBE(fe, be, svcKey.GetBackend()); err != nil {
			log.Errorf("%s", err)
			return
		}
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

func (cli *LBClient) RevNATAdd(id types.ServiceID, revNAT types.L3n4Addr) error {
	return lbmap.UpdateRevNat(lbmap.L3n4Addr2RevNatKeynValue(id, revNAT))
}

func (cli *LBClient) RevNATDelete(id types.ServiceID) error {
	// TODO Since we don't know if the ID belongs to IPv6 map or IPv4 map we try to
	// delete it first on IPv6. In case of success the deletion stops, in case of
	// failure tries to delete on the IPv4 map.
	revNATK6 := lbmap.NewRevNat6Key(uint16(id))
	err1 := lbmap.DeleteRevNat(revNATK6)
	if err1 == nil {
		return nil
	}

	revNATK4 := lbmap.NewRevNat4Key(uint16(id))
	if err := lbmap.DeleteRevNat(revNATK4); err != nil {
		return err1
	}
	return nil
}

func (cli *LBClient) RevNATDeleteAll() error {
	if err := lbmap.RevNat6Map.DeleteAll(); err != nil {
		log.Warningf("%s", err)
	}
	if err := lbmap.RevNat4Map.DeleteAll(); err != nil {
		log.Warningf("%s", err)
	}
	return nil
}

func (cli *LBClient) RevNATGet(id types.ServiceID) (*types.L3n4Addr, error) {
	revNATK6 := lbmap.NewRevNat6Key(uint16(id))
	revNat6V, err1 := lbmap.LookupRevNat(revNATK6)
	if err1 == nil {
		return lbmap.RevNat6Value2L3n4Addr(revNat6V.(*lbmap.RevNat6Value))
	}

	revNATK4 := lbmap.NewRevNat4Key(uint16(id))
	revNat4V, err := lbmap.LookupRevNat(revNATK4)
	if err != nil {
		return nil, err1
	}
	return lbmap.RevNat4Value2L3n4Addr(revNat4V.(*lbmap.RevNat4Value))
}

func (cli *LBClient) RevNATDump() ([]types.L3n4AddrID, error) {
	revNATs := types.RevNATMap{}

	parseRevNATEntries := func(key bpf.MapKey, value bpf.MapValue) {
		revNatK := key.(lbmap.RevNatKey)
		revNatV := value.(lbmap.RevNatValue)
		fe, err := lbmap.RevNatValue2L3n4AddrID(revNatK, revNatV)
		if err != nil {
			log.Errorf("%s", err)
			return
		}
		revNATs[fe.ID] = fe.L3n4Addr
	}

	if err := lbmap.RevNat4Map.Dump(lbmap.RevNat4DumpParser, parseRevNATEntries); err != nil {
		return nil, err
	}
	if err := lbmap.RevNat6Map.Dump(lbmap.RevNat6DumpParser, parseRevNATEntries); err != nil {
		return nil, err
	}

	dump := []types.L3n4AddrID{}
	for k, v := range revNATs {
		dump = append(dump, types.L3n4AddrID{
			ID:       k,
			L3n4Addr: v,
		})
	}
	return dump, nil
}

func (cli *LBClient) SyncLBMap() error {
	return NonAvailable
}
