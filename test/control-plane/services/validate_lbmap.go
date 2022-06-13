// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package services

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"testing"

	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/testutils/mockmaps"
	"github.com/pmezard/go-difflib/difflib"
	"golang.org/x/exp/constraints"
)

type goldenLBMapValidator struct {
	expectedFile string
	update       bool
}

func newGoldenLBMapValidator(eventsFile string, update bool) goldenLBMapValidator {
	var v goldenLBMapValidator
	var stepNum int
	fmt.Sscanf(path.Base(eventsFile), "events%d.yaml", &stepNum)
	v.expectedFile = path.Join(path.Dir(eventsFile), fmt.Sprintf("lbmap%d.golden", stepNum))
	v.update = update
	return v
}

func (v goldenLBMapValidator) diffStrings(expected, actual string) (string, bool) {
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

func (v goldenLBMapValidator) validate(t *testing.T, lbmap *mockmaps.LBMockMap) {
	writeLBMap := func() {
		f, err := os.OpenFile(v.expectedFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
		if err != nil {
			t.Fatal(err)
		}
		writeLBMapAsTable(f, lbmap)
		f.Close()
	}

	if _, err := os.Stat(v.expectedFile); err == nil {
		bs, err := os.ReadFile(v.expectedFile)
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		writeLBMapAsTable(&buf, lbmap)
		if diff, ok := v.diffStrings(string(bs), buf.String()); !ok {
			if v.update {
				t.Logf("lbmap mismatch:\n%s", diff)
				t.Logf("updated %s as requested", v.expectedFile)
				writeLBMap()
			} else {
				t.Fatalf("lbmap mismatch:\n%s", diff)
			}
		}
	} else {
		// Mark failed as the expected output was missing, but
		// continue with the rest of the steps.
		t.Fail()
		t.Logf("%s missing, creating...", v.expectedFile)
		writeLBMap()
	}
}

func writeLBMapAsTable(w io.Writer, lbmap *mockmaps.LBMockMap) {
	tw := newTableWriter(w, "Backends", "ID", "L3n4Addr", "FEPortName", "NodeName", "State", "Restored")
	MapInOrder(lbmap.BackendByID,
		func(_ lb.BackendID, be *lb.Backend) {
			stateStr, err := be.State.String()
			if err != nil {
				stateStr = err.Error()
			}

			tw.AddRow(
				fmt.Sprintf("%d", be.ID),
				be.L3n4Addr.String(),
				be.FEPortName,
				be.NodeName,
				stateStr,
				fmt.Sprintf("%v", be.RestoredFromDatapath))
		})
	tw.Flush()

	tw = newTableWriter(w, "Services", "ID" /*"Name", "Namespace",*/, "Type", "Backend IDs")
	MapInOrder(lbmap.ServiceByID,
		func(id uint16, svc *lb.SVC) {
			tw.AddRow(
				fmt.Sprintf("%d", id),
				/* FIXME: these are never set anywhere
				svc.Name,
				svc.Namespace,*/
				string(svc.Type),
				showBackendIDs(svc.Backends),
			)
		})
	tw.Flush()
}

func showBackendIDs(bes []lb.Backend) string {
	var ids []string
	for _, be := range bes {
		ids = append(ids, strconv.FormatUint(uint64(be.ID), 10))
	}
	return strings.Join(ids, ", ")
}

type orderedComparable interface {
	comparable
	constraints.Ordered
}

// MapInOrder does an in-order traversal of a map.
func MapInOrder[K orderedComparable, V any](m map[K]V, fn func(K, V)) {
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	for _, k := range keys {
		fn(k, m[k])
	}
}
