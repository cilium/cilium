// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of Cilium

package tests

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium-cli/connectivity/check"
)

const (
	messageSize = 1024
)

// Network Performance
func NetperfPodtoPod(n string) check.Scenario {
	return &netPerfPodtoPod{
		name: n,
	}
}

type netPerfPodtoPod struct {
	name string
}

var netPerfRegex = regexp.MustCompile(`\s+\d+\s+\d+\s+(\d+|\S+)\s+(\S+|\d+)\s+(\S+)+\s+(\S+)?`)

func (s *netPerfPodtoPod) Name() string {
	tn := "perf-pod-to-pod"
	if s.name == "" {
		return tn
	}
	return fmt.Sprintf("%s:%s", tn, s.name)
}

func (s *netPerfPodtoPod) Run(ctx context.Context, t *check.Test) {
	samples := t.Context().Params().PerfSamples
	duration := t.Context().Params().PerfDuration
	crr := t.Context().Params().PerfCRR
	for _, c := range t.Context().PerfClientPods() {
		c := c
		for _, server := range t.Context().PerfServerPod() {
			var scenarioName string
			if c.Pod.Spec.HostNetwork {
				scenarioName = "host-net"
			} else {
				scenarioName = "pod-net"
			}
			action := t.NewAction(s, "netperf", &c, server)
			action.CollectFlows = false
			action.Run(func(a *check.Action) {
				if crr {
					netperf(ctx, server.Pod.Status.PodIP, c.Pod.Name, "TCP_CRR", a, t.Context().PerfResults, 1, 30, scenarioName)
				} else {
					netperf(ctx, server.Pod.Status.PodIP, c.Pod.Name, "TCP_RR", a, t.Context().PerfResults, samples, duration, scenarioName)
					netperf(ctx, server.Pod.Status.PodIP, c.Pod.Name, "TCP_STREAM", a, t.Context().PerfResults, samples, duration, scenarioName)
					netperf(ctx, server.Pod.Status.PodIP, c.Pod.Name, "UDP_RR", a, t.Context().PerfResults, samples, duration, scenarioName)
					netperf(ctx, server.Pod.Status.PodIP, c.Pod.Name, "UDP_STREAM", a, t.Context().PerfResults, samples, duration, scenarioName)
				}
			})
		}
	}
}

func netperf(ctx context.Context, sip string, podname string, test string, a *check.Action, result map[check.PerfTests]check.PerfResult, samples int, duration time.Duration, scenarioName string) {
	// Define test about to be executed and from which pod
	k := check.PerfTests{
		Pod:  podname,
		Test: test,
	}
	metric := string("OP/s")
	if strings.Contains(test, "STREAM") {
		metric = "Mb/s"
	}

	exec := []string{"/usr/local/bin/netperf", "-H", sip, "-l", duration.String(), "-t", test, "--", "-R", "1", "-m", fmt.Sprintf("%d", messageSize)}
	//  recv socketsize		send socketsize 	msg size|okmsg	duration	value
	values := []float64{}
	// Result data
	for i := 0; i < samples; i++ {
		a.ExecInPod(ctx, exec)
		d := netPerfRegex.FindStringSubmatch(a.CmdOutput())
		if len(d) < 5 {
			a.Fatal("Unable to process netperf result")
		}
		nv := ""
		if len(d[len(d)-1]) > 0 {
			nv = d[len(d)-1]
		} else {
			nv = d[len(d)-2]
		}
		f, err := strconv.ParseFloat(nv, 64)
		if err == nil {
			values = append(values, f)
		} else {
			a.Fatal("Unable to parse netperf result")
		}
	}
	res := check.PerfResult{
		Scenario: scenarioName,
		Metric:   metric,
		Duration: duration,
		Values:   values,
		Samples:  samples,
		Avg:      listAvg(values),
	}
	result[k] = res
}

func listAvg(list []float64) float64 {
	total := 0.0
	for _, v := range list {
		total = total + v
	}
	return float64(total) / float64(len(list))
}
