/*
Copyright 2014 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sets

import (
	"net"
	"reflect"
	"sort"
	"testing"
)

func parseIPNet(s string) *net.IPNet {
	_, net, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return net
}

func TestIPNets(t *testing.T) {
	s := IPNet{}
	s2 := IPNet{}
	if len(s) != 0 {
		t.Errorf("Expected len=0: %d", len(s))
	}
	a := parseIPNet("1.0.0.0/8")
	b := parseIPNet("2.0.0.0/8")
	c := parseIPNet("3.0.0.0/8")
	d := parseIPNet("4.0.0.0/8")

	s.Insert(a, b)
	if len(s) != 2 {
		t.Errorf("Expected len=2: %d", len(s))
	}
	s.Insert(c)
	if s.Has(d) {
		t.Errorf("Unexpected contents: %#v", s)
	}
	if !s.Has(a) {
		t.Errorf("Missing contents: %#v", s)
	}
	s.Delete(a)
	if s.Has(a) {
		t.Errorf("Unexpected contents: %#v", s)
	}
	s.Insert(a)
	if s.HasAll(a, b, d) {
		t.Errorf("Unexpected contents: %#v", s)
	}
	if !s.HasAll(a, b) {
		t.Errorf("Missing contents: %#v", s)
	}
	s2.Insert(a, b, d)
	if s.IsSuperset(s2) {
		t.Errorf("Unexpected contents: %#v", s)
	}
	s2.Delete(d)
	if !s.IsSuperset(s2) {
		t.Errorf("Missing contents: %#v", s)
	}
}

func TestIPNetSetDeleteMultiples(t *testing.T) {
	s := IPNet{}
	a := parseIPNet("1.0.0.0/8")
	b := parseIPNet("2.0.0.0/8")
	c := parseIPNet("3.0.0.0/8")

	s.Insert(a, b, c)
	if len(s) != 3 {
		t.Errorf("Expected len=3: %d", len(s))
	}

	s.Delete(a, c)
	if len(s) != 1 {
		t.Errorf("Expected len=1: %d", len(s))
	}
	if s.Has(a) {
		t.Errorf("Unexpected contents: %#v", s)
	}
	if s.Has(c) {
		t.Errorf("Unexpected contents: %#v", s)
	}
	if !s.Has(b) {
		t.Errorf("Missing contents: %#v", s)
	}
}

func TestNewIPSet(t *testing.T) {
	s, err := ParseIPNets("1.0.0.0/8", "2.0.0.0/8", "3.0.0.0/8")
	if err != nil {
		t.Errorf("error parsing IPNets: %v", err)
	}
	if len(s) != 3 {
		t.Errorf("Expected len=3: %d", len(s))
	}
	a := parseIPNet("1.0.0.0/8")
	b := parseIPNet("2.0.0.0/8")
	c := parseIPNet("3.0.0.0/8")

	if !s.Has(a) || !s.Has(b) || !s.Has(c) {
		t.Errorf("Unexpected contents: %#v", s)
	}
}

func TestIPNetSetDifference(t *testing.T) {
	l, err := ParseIPNets("1.0.0.0/8", "2.0.0.0/8", "3.0.0.0/8")
	if err != nil {
		t.Errorf("error parsing IPNets: %v", err)
	}
	r, err := ParseIPNets("1.0.0.0/8", "2.0.0.0/8", "4.0.0.0/8", "5.0.0.0/8")
	if err != nil {
		t.Errorf("error parsing IPNets: %v", err)
	}
	c := l.Difference(r)
	d := r.Difference(l)
	if len(c) != 1 {
		t.Errorf("Expected len=1: %d", len(c))
	}
	if !c.Has(parseIPNet("3.0.0.0/8")) {
		t.Errorf("Unexpected contents: %#v", c)
	}
	if len(d) != 2 {
		t.Errorf("Expected len=2: %d", len(d))
	}
	if !d.Has(parseIPNet("4.0.0.0/8")) || !d.Has(parseIPNet("5.0.0.0/8")) {
		t.Errorf("Unexpected contents: %#v", d)
	}
}

func TestIPNetSetList(t *testing.T) {
	s, err := ParseIPNets("3.0.0.0/8", "1.0.0.0/8", "2.0.0.0/8")
	if err != nil {
		t.Errorf("error parsing IPNets: %v", err)
	}
	l := s.StringSlice()
	sort.Strings(l)
	if !reflect.DeepEqual(l, []string{"1.0.0.0/8", "2.0.0.0/8", "3.0.0.0/8"}) {
		t.Errorf("List gave unexpected result: %#v", l)
	}
}
