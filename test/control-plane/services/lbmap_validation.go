// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package services

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/pmezard/go-difflib/difflib"
	"golang.org/x/exp/constraints"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"

	fakeDatapath "github.com/cilium/cilium/pkg/datapath/fake"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/testutils/mockmaps"
	controlplane "github.com/cilium/cilium/test/control-plane"
)

func NewGoldenServicesTest(t *testing.T, nodeName string) *controlplane.ControlPlaneTestCase {
	return controlplane.NewGoldenTest(t, nodeName, newGoldenLBMapValidator)
}

type goldenLBMapValidator struct {
	expectedFile string
	update       bool
}

func newGoldenLBMapValidator(stateFile string, update bool) controlplane.Validator {
	var v goldenLBMapValidator
	var stepNum int
	n, err := fmt.Sscanf(path.Base(stateFile), "state%d.yaml", &stepNum)
	if n != 1 || err != nil {
		panic(fmt.Sprintf("newGoldenLBMapValidator: failed to parse %q, did not match pattern 'state%%d.yaml' (n=%d, err=%s)", stateFile, n, err))
	}
	v.expectedFile = path.Join(path.Dir(stateFile), fmt.Sprintf("lbmap%d.golden", stepNum))
	v.update = update
	return &v
}

func (v *goldenLBMapValidator) diffStrings(expected, actual string) (string, bool) {
	diff := difflib.UnifiedDiff{
		A:        difflib.SplitLines(expected),
		B:        difflib.SplitLines(actual),
		FromFile: v.expectedFile,
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

func (v *goldenLBMapValidator) Validate(datapath *fakeDatapath.FakeDatapath) error {
	lbmap := datapath.LBMockMap()
	writeLBMap := func() error {
		f, err := os.OpenFile(v.expectedFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		writeLBMapAsTable(f, lbmap)
		f.Close()
		return nil
	}

	if _, err := os.Stat(v.expectedFile); err == nil {
		bs, err := os.ReadFile(v.expectedFile)
		if err != nil {
			return err
		}
		var buf bytes.Buffer
		writeLBMapAsTable(&buf, lbmap)
		if diff, ok := v.diffStrings(string(bs), buf.String()); !ok {
			if v.update {
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

func ipLess(a, b net.IP) bool {
	nipA, _ := netip.AddrFromSlice(a)
	nipB, _ := netip.AddrFromSlice(b)
	return nipA.Compare(nipB) < 0
}

func l3n4AddrLess(a, b *lb.L3n4Addr) bool {
	if a.Protocol < b.Protocol {
		return true
	} else if a.Protocol > b.Protocol {
		return false
	}
	if ipLess(a.IP, b.IP) {
		return true
	}
	return a.Port < b.Port
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

	tw := controlplane.NewEmptyTable("Services", "ID", "Name", "Type", "Frontend", "Backend IDs")
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

	tw = controlplane.NewEmptyTable("Backends", "ID", "L3n4Addr", "State", "Linked Services")
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
