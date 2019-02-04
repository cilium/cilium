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

package alignchecker

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
#include "sockops/bpf_sockops.h"
*/
import "C"

import (
	"fmt"
	"os"
	"reflect"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/configmap"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/metricsmap"
	"github.com/cilium/cilium/pkg/maps/sockmap"
)

func compareStructs(cStruct reflect.Type, vtc valueToCheck) error {
	goStruct := vtc.goStruct
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
	goSize := goStruct.Size()
	if vtc.sizeOfC != goSize {
		return fmt.Errorf("C struct %q (%d) has different size than GoStruct %q (%d)",
			cStruct.Name(), vtc.sizeOfC, goStruct.Name(), goSize)
	}
	return nil
}

type valueToCheck struct {
	sizeOfC  uintptr
	goStruct reflect.Type
}

var cToGO = map[reflect.Type]valueToCheck{
	reflect.TypeOf(C.struct_ipv4_ct_tuple{}): {
		sizeOfC:  C.sizeof_struct_ipv4_ct_tuple,
		goStruct: reflect.TypeOf(ctmap.CtKey4{}),
	},
	reflect.TypeOf(C.struct_ipv6_ct_tuple{}): {
		sizeOfC:  C.sizeof_struct_ipv6_ct_tuple,
		goStruct: reflect.TypeOf(ctmap.CtKey6{}),
	},
	reflect.TypeOf(C.struct_ct_entry{}): {
		sizeOfC:  C.sizeof_struct_ct_entry,
		goStruct: reflect.TypeOf(ctmap.CtEntry{}),
	},
	reflect.TypeOf(C.struct_ipcache_key{}): {
		sizeOfC:  C.sizeof_struct_ipcache_key,
		goStruct: reflect.TypeOf(ipcache.Key{}),
	},
	reflect.TypeOf(C.struct_remote_endpoint_info{}): {
		sizeOfC:  C.sizeof_struct_remote_endpoint_info,
		goStruct: reflect.TypeOf(ipcache.RemoteEndpointInfo{}),
	},
	reflect.TypeOf(C.struct_lb4_key{}): {
		sizeOfC:  C.sizeof_struct_lb4_key,
		goStruct: reflect.TypeOf(lbmap.Service4Key{}),
	},
	reflect.TypeOf(C.struct_lb4_service{}): {
		sizeOfC:  C.sizeof_struct_lb4_service,
		goStruct: reflect.TypeOf(lbmap.Service4Value{}),
	},
	reflect.TypeOf(C.struct_lb6_key{}): {
		sizeOfC:  C.sizeof_struct_lb6_key,
		goStruct: reflect.TypeOf(lbmap.Service6Key{}),
	},
	reflect.TypeOf(C.struct_lb6_service{}): {
		sizeOfC:  C.sizeof_struct_lb6_service,
		goStruct: reflect.TypeOf(lbmap.Service6Value{}),
	},
	reflect.TypeOf(C.struct_endpoint_key{}): {
		sizeOfC:  C.sizeof_struct_endpoint_key,
		goStruct: reflect.TypeOf(bpf.EndpointKey{}),
	},
	reflect.TypeOf(C.struct_endpoint_info{}): {
		sizeOfC:  C.sizeof_struct_endpoint_info,
		goStruct: reflect.TypeOf(lxcmap.EndpointInfo{}),
	},
	reflect.TypeOf(C.struct_metrics_key{}): {
		sizeOfC:  C.sizeof_struct_metrics_key,
		goStruct: reflect.TypeOf(metricsmap.Key{}),
	},
	reflect.TypeOf(C.struct_metrics_value{}): {
		sizeOfC:  C.sizeof_struct_metrics_value,
		goStruct: reflect.TypeOf(metricsmap.Value{}),
	},
	reflect.TypeOf(C.struct_sock_key{}): {
		sizeOfC:  C.sizeof_struct_sock_key,
		goStruct: reflect.TypeOf(sockmap.SockmapKey{}),
	},
	reflect.TypeOf(C.struct_ep_config{}): {
		sizeOfC:  C.sizeof_struct_ep_config,
		goStruct: reflect.TypeOf(configmap.EndpointConfig{}),
	},
}

func init() {
	for k, v := range cToGO {
		err := compareStructs(k, v)
		if err != nil {
			fmt.Fprintf(os.Stderr, "different structure types for CGO and GO: %s != %s\n", k, v.goStruct)
			panic(err)
		}
	}
}
