// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"flag"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"reflect"
	"slices"
	"unicode"
	"unicode/utf8"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/ir"

	"k8s.io/apimachinery/pkg/util/sets"
)

type layerTuple struct {
	name string
	pb   any
	ir   any
}

var (
	// excludedFields omit L4/L7 layers from the traversal.
	// These will be handled on a case by case basis.
	excludedFields = sets.New("L4", "L7")

	// layers Need to manually track l4 and l7 layers
	// so we can check for diffs without building corresponding pb flows
	layers = []layerTuple{
		{"TCP", flowpb.TCP{}, ir.TCP{}},
		{"UDP", flowpb.UDP{}, ir.UDP{}},
		{"SCTP", flowpb.SCTP{}, ir.SCTP{}},
		{"ICMPv4", flowpb.ICMPv4{}, ir.ICMP{}},
		{"ICMPv6", flowpb.ICMPv6{}, ir.ICMP{}},
		{"DNS", flowpb.DNS{}, ir.DNS{}},
		{"HTTP", flowpb.HTTP{}, ir.HTTP{}},
	}

	// IR treats these types differently and thus
	// should be omitted from the deltas.
	excludedTags = sets.New("is_reply,omitempty", "time,omitempty")
)

func initLogger(level string) {
	var l slog.Level
	switch level {
	case "debug":
		l = slog.LevelDebug
	case "info":
		l = slog.LevelInfo
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelWarn
	}
	opts := &slog.HandlerOptions{
		Level: l,
	}
	handler := slog.NewTextHandler(os.Stdout, opts)
	slog.SetDefault(slog.New(handler))
}

// POC tool to compare IR vs Protobuf flows deltas.
// Traverses json struct tags and check for CRUD differences between PB and IR flows.
func main() {
	var logLevel string
	flag.StringVar(&logLevel, "v", "warn", "set the log level (debug, info, warn, error)")
	flag.Parse()
	initLogger(logLevel)

	for _, layer := range layers {
		acc1, acc2 := sets.New[string](), sets.New[string]()
		traverse("", layer.pb, acc1)
		traverse("", layer.ir, acc2)
		if computeDeltas(slog.Default(), acc1, acc2, "PB-"+layer.name, "IR-"+layer.name) {
			os.Exit(1)
		}
	}

	pbAcc, irAcc := sets.New[string](), sets.New[string]()
	traverse("", flowpb.Flow{}, pbAcc)
	traverse("", ir.Flow{}, irAcc)
	if computeDeltas(slog.Default(), irAcc, pbAcc, "IR", "PB") {
		os.Exit(1)
	}
}

func computeDeltas(logger *slog.Logger, s1, s2 sets.Set[string], t1, t2 string) bool {
	diff1 := s1.Difference(s2)
	if diff1.Len() > 0 {
		dumpSet("> "+t1+" Flow Diff", diff1)
		return true
	}

	diff2 := s2.Difference(s1)
	if diff2.Len() > 0 {
		dumpSet("< "+t2+" Flow Diff", diff2)
		return true
	}
	logger.Debug("No flow deltas detected")

	return false
}

func dumpSet(title string, s sets.Set[string]) {
	if s.Len() == 0 {
		fmt.Println("\n-----", title, "-----")
		fmt.Println("<empty set>")
		return
	}

	kk := slices.Collect(maps.Keys(s))
	slices.Sort(kk)
	fmt.Println("\n-----", title, "-----")
	for _, k := range kk {
		fmt.Println(k)
	}
}

func getType(a any) reflect.Type {
	t := reflect.TypeOf(a)
	switch t.Kind() {
	case reflect.Pointer:
		return t.Elem()
	case reflect.Slice, reflect.Map:
		e := t.Elem()
		if e.Kind() == reflect.Pointer {
			e = e.Elem()
		}
		return getType(e)
	default:
		return t
	}
}

func traverse(p string, x any, acc sets.Set[string]) {
	if x == nil {
		return
	}

	t := getType(x)
	if !isCustomType(t) {
		return
	}
	for field := range t.Fields() {
		if !isExported(field.Name) || excludedFields.Has(field.Name) {
			continue
		}

		tag := field.Tag.Get("json")
		if tag == "" || excludedTags.Has(tag) {
			continue
		}

		if p != "" {
			tag = p + "." + tag
		}

		val := field.Type
		if isCustomType(val) {
			traverse(tag, reflect.New(val).Elem().Interface(), acc)
		}
		acc.Insert(tag)
	}
}

func isCustomType(t reflect.Type) bool {
	if t == nil {
		return false
	}

	switch t.Kind() {
	case reflect.Pointer:
		return isCustomType(t.Elem())
	case reflect.Struct, reflect.Interface:
		return true
	case reflect.Slice, reflect.Map:
		e := t.Elem()
		if e.Kind() == reflect.Pointer {
			e = e.Elem()
		}
		return isCustomType(e)
	default:
		return false
	}
}

func isExported(s string) bool {
	if len(s) == 0 {
		return false
	}
	r, _ := utf8.DecodeRuneInString(s)

	return unicode.IsUpper(r)
}
