// Copyright 2018 Authors of Cilium
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

package align_checker

/*
#cgo CFLAGS: -I./../../bpf/lib -I./../../bpf/include -I ./../../bpf -D__NR_CPUS__=1
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <linux/byteorder.h>
#include <linux/unistd.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <sys/resource.h>
#include "node_config.h"
#include "lib/conntrack.h"
#include "lib/maps.h"
*/
import "C"

import (
	"fmt"
	"os"
	"reflect"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/metricsmap"
	"github.com/cilium/cilium/pkg/maps/proxymap"
)

func compareStructs(cStruct, goStruct reflect.Type) error {
	for i := 0; i < cStruct.NumField(); i++ {
		cField := cStruct.Field(i)
		goField := goStruct.Field(i)
		if cField.Offset != goField.Offset {
			cPrevField := cStruct.Field(i - 1)
			goPrevField := goStruct.Field(i - 1)
			cFieldSize := cField.Offset - cPrevField.Offset
			goFieldSize := goField.Offset - goPrevField.Offset
			return fmt.Errorf("C struct field %q (%d) has different size than GoStruct field %q (%d)",
				cPrevField.Name, cFieldSize, goPrevField.Name, goFieldSize)
		}
	}
	if cStruct.Size() != goStruct.Size() {
		return fmt.Errorf("C struct %q (%d) has different size than GoStruct %q (%d)",
			cStruct.Name(), cStruct.Size(), goStruct.Name(), goStruct.Size())
	}
	return nil
}

var cToGO = map[reflect.Type]reflect.Type{
	reflect.TypeOf(C.struct_ipv4_ct_tuple{}):        reflect.TypeOf(ctmap.CtKey4{}),
	reflect.TypeOf(C.struct_ipv6_ct_tuple{}):        reflect.TypeOf(ctmap.CtKey6{}),
	reflect.TypeOf(C.struct_ct_entry{}):             reflect.TypeOf(ctmap.CtEntry{}),
	reflect.TypeOf(C.struct_ipcache_key{}):          reflect.TypeOf(ipcache.Key{}),
	reflect.TypeOf(C.struct_remote_endpoint_info{}): reflect.TypeOf(ipcache.RemoteEndpointInfo{}),
	reflect.TypeOf(C.struct_lb4_key{}):              reflect.TypeOf(lbmap.Service4Key{}),
	reflect.TypeOf(C.struct_lb4_service{}):          reflect.TypeOf(lbmap.Service4Value{}),
	reflect.TypeOf(C.struct_lb6_key{}):              reflect.TypeOf(lbmap.Service6Key{}),
	reflect.TypeOf(C.struct_lb6_service{}):          reflect.TypeOf(lbmap.Service6Value{}),
	reflect.TypeOf(C.struct_endpoint_key{}):         reflect.TypeOf(bpf.EndpointKey{}),
	reflect.TypeOf(C.struct_endpoint_info{}):        reflect.TypeOf(lxcmap.EndpointInfo{}),
	reflect.TypeOf(C.struct_metrics_key{}):          reflect.TypeOf(metricsmap.Key{}),
	reflect.TypeOf(C.struct_metrics_value{}):        reflect.TypeOf(metricsmap.Value{}),
	reflect.TypeOf(C.struct_proxy4_tbl_key{}):       reflect.TypeOf(proxymap.Proxy4Key{}),
	reflect.TypeOf(C.struct_proxy4_tbl_value{}):     reflect.TypeOf(proxymap.Proxy4Value{}),
	reflect.TypeOf(C.struct_proxy6_tbl_key{}):       reflect.TypeOf(proxymap.Proxy6Key{}),
	reflect.TypeOf(C.struct_proxy6_tbl_value{}):     reflect.TypeOf(proxymap.Proxy6Value{}),
}

func init() {
	for k, v := range cToGO {
		err := compareStructs(k, v)
		if err != nil {
			fmt.Fprintf(os.Stderr, "different structure types for CGO and GO: %s != %s\n", k, v)
			panic(err)
		}
	}
}
