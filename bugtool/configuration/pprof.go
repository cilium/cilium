// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package configuration

import (
	"fmt"

	"github.com/cilium/cilium/bugtool/dump"
	"github.com/cilium/cilium/bugtool/options"
)

func GetPProf(conf *options.Config) dump.Tasks {
	pprofHost := fmt.Sprintf("localhost:%d", conf.PprofPort)
	ts := dump.Tasks{}
	ts = append(ts, dump.NewRequest("pprof-profile", fmt.Sprintf("http://%s/debug/pprof/profile?seconds=%d", pprofHost, conf.PProfTraceSeconds)))
	ts = append(ts, dump.NewRequest("pprof-trace", fmt.Sprintf("http://%s/debug/pprof/trace?seconds=%d", pprofHost, conf.PProfTraceSeconds)))
	ts = append(ts, dump.NewRequest("pprof-heap", fmt.Sprintf("http://%s/debug/pprof/heap?debug=%d", pprofHost, conf.PprofDebug)))
	return ts
}
