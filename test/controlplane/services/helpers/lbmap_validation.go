// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/pmezard/go-difflib/difflib"
	"golang.org/x/exp/constraints"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"

	fakeDatapath "github.com/cilium/cilium/pkg/datapath/fake"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/testutils/mockmaps"
	"github.com/cilium/cilium/test/controlplane/suite"
)

func ValidateLBMapGoldenFile(file string, datapath *fakeDatapath.FakeDatapath) error {
	lbmap := datapath.LBMockMap()
	writeLBMap := func() error {
		f, err := os.OpenFile(file, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		writeLBMapAsTable(f, lbmap)
		f.Close()
		return nil
	}

	if _, err := os.Stat(file); err == nil {
		bs, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		var buf bytes.Buffer
		writeLBMapAsTable(&buf, lbmap)
		if diff, ok := diffStrings(file, string(bs), buf.String()); !ok {
			if *suite.FlagUpdate {
				return writeLBMap()
			} else {
				return fmt.Errorf("lbmap mismatch:\n%s", diff)
			}
		}
		return nil
	} else {
		// Mark failed as the expected output was missing, but
		// continue with the rest of the steps.
		return writeLBMap()
	}
}

func diffStrings(file string, expected, actual string) (string, bool) {
	diff := difflib.UnifiedDiff{
		A:        difflib.SplitLines(expected),
		B:        difflib.SplitLines(actual),
		FromFile: file,
		ToFile:   "<actual>",
		Context:  10,
	}
	out, err := difflib.GetUnifiedDiffString(diff)
	if err != nil {
		return err.Error(), false
	}
	if out != "" {
		return out, false
	}
	return "", true
}

func writeLBMapAsTable(w io.Writer, lbmap *mockmaps.LBMockMap) {
	lbmap.Lock()
	defer lbmap.Unlock()

	// Since the order in which backends and services (and their ids)
	// are allocated is non-deterministic, we sort the backends and services
	// by address, and use the new ordering to allocate deterministic ids.
	backends := make([]*lb.Backend, 0, len(lbmap.BackendByID))
	for _, be := range lbmap.BackendByID {
		backends = append(backends, be)
	}
	sort.Slice(backends, func(i, j int) bool {
		return backends[i].L3n4Addr.StringWithProtocol() < backends[j].StringWithProtocol()
	})
	newBackendIds := map[lb.BackendID]int{}
	for i, be := range backends {
		newBackendIds[be.ID] = i
	}

	services := make([]*lb.SVC, 0, len(lbmap.ServiceByID))
	for _, svc := range lbmap.ServiceByID {
		services = append(services, svc)
	}
	// Sort services by type, then namespace/name and finally by frontend address.
	sort.Slice(services, func(i, j int) bool {
		if services[i].Type < services[j].Type {
			return true
		} else if services[i].Type > services[j].Type {
			return false
		}
		if services[i].Name.Namespace < services[j].Name.Namespace {
			return true
		} else if services[i].Name.Namespace > services[j].Name.Namespace {
			return false
		}
		if services[i].Name.Name < services[j].Name.Name {
			return true
		} else if services[i].Name.Name > services[j].Name.Name {
			return false
		}
		return services[i].Frontend.L3n4Addr.StringWithProtocol() <
			services[j].Frontend.L3n4Addr.StringWithProtocol()
	})

	// Map for linking backend to services that refer to it.
	backendToServiceId := make(map[int][]string)

	tw := suite.NewEmptyTable("Services", "ID", "Name", "Type", "Frontend", "Backend IDs")
	for i, svc := range services {
		for _, be := range svc.Backends {
			id := newBackendIds[be.ID]
			backendToServiceId[id] = append(backendToServiceId[id], strconv.FormatInt(int64(i), 10))
		}
		tw.AddRow(
			strconv.FormatInt(int64(i), 10),
			svc.Name.String(),
			string(svc.Type),
			svc.Frontend.StringWithProtocol(),
			showBackendIDs(newBackendIds, svc.Backends),
		)
	}
	tw.Write(w)

	tw = suite.NewEmptyTable("Backends", "ID", "L3n4Addr", "State", "Linked Services")
	for i, be := range backends {
		stateStr, err := be.State.String()
		if err != nil {
			stateStr = err.Error()
		}
		tw.AddRow(
			strconv.FormatInt(int64(i), 10),
			be.L3n4Addr.StringWithProtocol(),
			stateStr,
			strings.Join(backendToServiceId[i], ", "),
		)
	}
	tw.Write(w)

}

func showBackendIDs(idMap map[lb.BackendID]int, bes []*lb.Backend) string {
	var ids []int
	for _, be := range bes {
		ids = append(ids, idMap[be.ID])
	}
	sort.Ints(ids)
	var strs []string
	for _, id := range ids {
		strs = append(strs, strconv.FormatInt(int64(id), 10))
	}
	return strings.Join(strs, ", ")
}

// MapInOrder does an in-order traversal of a map.
func MapInOrder[M ~map[K]V, K constraints.Ordered, V any](m M, fn func(K, V)) {
	keys := maps.Keys(m)
	slices.Sort(keys)
	for _, k := range keys {
		fn(k, m[k])
	}
}
