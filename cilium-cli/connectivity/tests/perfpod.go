// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/utils/features"
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
var netPerfRegexLatency = regexp.MustCompile(`(\d+(?:\.\d+)?),(\d+(?:\.\d+)?),(\d+(?:\.\d+)?),(\d+(?:\.\d+)?),(\d+(?:\.\d+)?),(\d+(?:\.\d+)?)`)

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
	latency := t.Context().Params().PerfLatency
	for _, c := range t.Context().PerfClientPods() {
		c := c
		for _, server := range t.Context().PerfServerPod() {
			var scenarioName string
			if c.Pod.Spec.HostNetwork {
				scenarioName = "host-net"
			} else {
				scenarioName = "pod-net"
			}
			action := t.NewAction(s, "netperf", &c, server, features.IPFamilyV4)
			action.CollectFlows = false
			action.Run(func(a *check.Action) {
				if crr {
					netperf(ctx, server.Pod.Status.PodIP, c.Pod.Name, "TCP_CRR", a, t.Context().PerfResults, samples, duration, scenarioName)
				} else if latency {
					netperf(ctx, server.Pod.Status.PodIP, c.Pod.Name, "TCP_RR_LATENCY", a, t.Context().PerfResults, samples, duration, scenarioName)
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

func buildExecCommand(test string, sip string, duration time.Duration, args []string) []string {
	exec := []string{"/usr/local/bin/netperf", "-H", sip, "-l", duration.String(), "-t", test, "--", "-R", "1", "-m", fmt.Sprintf("%d", messageSize)}
	exec = append(exec, args...)

	return exec
}

func netperf(ctx context.Context, sip string, podname string, test string, a *check.Action, result map[check.PerfTests]check.PerfResult, samples int, duration time.Duration, scenarioName string) {
	// Define test about to be executed and from which pod
	k := check.PerfTests{
		Pod:  podname,
		Test: test,
	}

	res := check.PerfResult{
		Duration: duration,
		Samples:  samples,
		Scenario: scenarioName,
	}

	if strings.Contains(test, "LATENCY") {
		test = strings.ReplaceAll(test, "_LATENCY", "")
		k.Test = test
		metric := string("μs")
		latency := make(map[string][]float64)

		args := []string{"-o", "min_latency,mean_latency,max_latency,P50_LATENCY,P90_LATENCY,P99_LATENCY"}
		exec := buildExecCommand(test, sip, duration, args)

		latencyMetricNames := []string{
			"min", "mean", "max", "p50", "p90", "p99",
		}

		var latencyMetricValue float64
		var err error
		for i := 0; i < samples; i++ {
			a.ExecInPod(ctx, exec)
			d := netPerfRegexLatency.FindStringSubmatch(a.CmdOutput())

			if len(d) != 7 {
				a.Fatal("Unable to process netperf result")
			}

			for m, metric := range latencyMetricNames {
				latencyMetricValue, err = strconv.ParseFloat(d[m+1], 64)
				if err != nil {
					a.Fatal(fmt.Sprintf("Unable to parse netperf result %s", metric))
				}
				latency[metric] = append(latency[metric], latencyMetricValue)
			}
		}

		for _, metric := range latencyMetricNames {
			latency[metric] = []float64{listAvg(latency[metric])}
		}

		res.Metric = metric
		res.Latency = latency
	} else {
		metric := string("OP/s")
		if strings.Contains(test, "STREAM") {
			metric = "Mb/s"
		}

		exec := buildExecCommand(test, sip, duration, []string{})
		//  recv socketsize		send socketsize 	msg size|okmsg	duration	value
		// Result data
		values := []float64{}
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

		res.Metric = metric
		res.Values = values
		res.Avg = listAvg(values)
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
