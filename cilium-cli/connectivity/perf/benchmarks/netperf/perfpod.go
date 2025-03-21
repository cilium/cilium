// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package netperf

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/perf/benchmarks/profiler"
	"github.com/cilium/cilium/cilium-cli/connectivity/perf/common"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

const (
	netperfToolName = "netperf"
)

// Network Performance
func Netperf(n string) check.Scenario {
	return &netPerf{
		name:         n,
		ScenarioBase: check.NewScenarioBase(),
	}
}

type netPerf struct {
	check.ScenarioBase

	name string
}

func (s *netPerf) Name() string {
	if s.name == "" {
		return netperfToolName
	}
	return fmt.Sprintf("%s:%s", netperfToolName, s.name)
}

func (s *netPerf) Run(ctx context.Context, t *check.Test) {
	perfParameters := t.Context().Params().PerfParameters

	profilingPods := t.Context().PerfProfilingPods()
	serverProfiler := profiler.New(profilingPods[check.PerfServerProfilingDeploymentName], perfParameters)
	clientProfiler := profiler.New(profilingPods[check.PerfClientProfilingAcrossDeploymentName], perfParameters)

	tests := []string{}

	if perfParameters.Throughput {
		tests = append(tests, "TCP_STREAM")
		if perfParameters.UDP {
			tests = append(tests, "UDP_STREAM")
		}
	}

	if perfParameters.ThroughputMulti {
		tests = append(tests, "TCP_STREAM_MULTI")
		if perfParameters.UDP {
			tests = append(tests, "UDP_STREAM_MULTI")
		}
	}

	if perfParameters.CRR {
		tests = append(tests, "TCP_CRR")
	}

	if perfParameters.RR {
		tests = append(tests, "TCP_RR")
		if perfParameters.UDP {
			tests = append(tests, "UDP_RR")
		}
	}

	if perfParameters.SetupDelay > 0 {
		t.Context().Logf("⌛ Waiting %v before starting performance tests", perfParameters.SetupDelay)
		select {
		case <-time.After(perfParameters.SetupDelay):
		case <-ctx.Done():
			return
		}
		t.Context().Info("Finished waiting before starting performance tests")
	}

	for sample := 1; sample <= perfParameters.Samples; sample++ {
		for _, c := range t.Context().PerfClientPods() {
			c := c
			for _, server := range t.Context().PerfServerPod() {
				clientHost := strings.Contains(c.Pod.Name, check.PerfHostName)
				serverHost := strings.Contains(server.Pod.Name, check.PerfHostName)

				switch {
				case clientHost && serverHost && perfParameters.HostNet:
				case clientHost && !serverHost && perfParameters.HostToPod:
				case !clientHost && serverHost && perfParameters.PodToHost:
				case !clientHost && !serverHost && perfParameters.PodNet:

				default:
					continue
				}

				scenarioName := ""
				if strings.Contains(c.Pod.Name, check.PerfHostName) {
					scenarioName += "host"
				} else {
					scenarioName += "pod"
				}
				scenarioName += "-to-"
				if strings.Contains(server.Pod.Name, check.PerfHostName) {
					scenarioName += "host"
				} else {
					scenarioName += "pod"
				}

				sameNode, nodeType := true, "same-node"
				if strings.Contains(c.Pod.Name, check.PerfOtherNode) {
					sameNode, nodeType = false, "other-node"
				}

				for _, test := range tests {
					testName := netperfToolName + "_" + test + "_" + scenarioName + "_" + nodeType
					action := t.NewAction(s, testName, &c, server, features.IPFamilyV4)

					action.CollectFlows = false
					action.Run(func(a *check.Action) {
						k := common.PerfTests{
							Test:     test,
							Tool:     netperfToolName,
							SameNode: sameNode,
							Sample:   sample,
							Duration: perfParameters.Duration,
							Streams:  perfParameters.Streams,
							Scenario: scenarioName,
							MsgSize:  perfParameters.MessageSize,
							NetQos:   false,
						}

						var clientProfile *profiler.Profile
						serverProfile := serverProfiler.Run(ctx, a)
						if !sameNode {
							clientProfile = clientProfiler.Run(ctx, a)
						}

						perfResult := NetperfCmd(ctx, server.Pod.Status.PodIP, k, a)
						t.Context().PerfResults = append(t.Context().PerfResults, common.PerfSummary{PerfTest: k, Result: perfResult})

						if err := serverProfile.Save(testName+"_server.perf", a); err != nil {
							a.Fatalf("Failed capturing kernel profile on server node: %v", err)
						}

						if !sameNode {
							if err := clientProfile.Save(testName+"_client.perf", a); err != nil {
								a.Fatalf("Failed capturing kernel profile on client node: %v", err)
							}
						}
					})
				}
			}
		}
	}
}

func buildExecCommand(test string, sip string, duration time.Duration, args []string) []string {
	exec := []string{"/usr/local/bin/netperf", "-H", sip, "-l", duration.String(), "-t", test, "--", "-R", "1"}
	exec = append(exec, args...)

	return exec
}

func parseDuration(a action, value string) time.Duration {
	res, err := time.ParseDuration(value + "us") // by default latencies in netperf are reported in microseconds
	if err != nil {
		a.Fatalf("Unable to process netperf result, duration: %s", value)
	}
	return res
}

func parseFloat(a action, value string) float64 {
	res, err := strconv.ParseFloat(value, 64)
	if err != nil {
		a.Fatalf("Unable to process netperf result, float: %s", value)
	}
	return res
}

func parseNetperfResult(a action, test, line string) common.PerfResult {
	values := strings.Split(line, ",")
	if len(values) != 9 {
		a.Fatalf("Unable to process netperf result")
	}
	a.Debugf("Numbers: %v", values)

	res := common.PerfResult{
		Timestamp: time.Now(),
		Latency: &common.LatencyMetric{
			Min:    parseDuration(a, values[0]),
			Avg:    parseDuration(a, values[1]),
			Max:    parseDuration(a, values[2]),
			Perc50: parseDuration(a, values[3]),
			Perc90: parseDuration(a, values[4]),
			Perc99: parseDuration(a, values[5]),
		},
		TransactionRateMetric: &common.TransactionRateMetric{
			TransactionRate: parseFloat(a, values[6]),
		},
		ThroughputMetric: &common.ThroughputMetric{
			Throughput: parseFloat(a, values[7]) * 1000000, // by default throughput has unit "10^6bits/s", we verify that later
		},
	}

	if strings.HasSuffix(test, "_STREAM") {
		// We don't want to report transaction rate or latency
		res.TransactionRateMetric = nil
		res.Latency = nil
		// Verify that throughput unit is 10^6bits/s
		if values[8] != "10^6bits/s" {
			a.Fatalf("Unable to process netperf result")
		}
	}
	if strings.HasSuffix(test, "_RR") || strings.HasSuffix(test, "_CRR") {
		// We don't want to report throughput
		res.ThroughputMetric = nil
	}

	return res
}

type action interface {
	ExecInPod(ctx context.Context, cmd []string)
	CmdOutput() string

	Debugf(format string, args ...any)
	Fatalf(format string, args ...any)
}

func NetperfCmd(ctx context.Context, sip string, perfTest common.PerfTests, a action) common.PerfResult {
	test := strings.TrimSuffix(perfTest.Test, "_MULTI")

	streams := uint(1)
	if strings.HasSuffix(perfTest.Test, "_MULTI") {
		streams = perfTest.Streams

		if !strings.HasSuffix(test, "_STREAM") {
			a.Fatalf("Only STREAM tests support parallelism")
		}
	}

	args := []string{"-o", "MIN_LATENCY,MEAN_LATENCY,MAX_LATENCY,P50_LATENCY,P90_LATENCY,P99_LATENCY,TRANSACTION_RATE,THROUGHPUT,THROUGHPUT_UNITS"}
	if test == "UDP_STREAM" || perfTest.NetQos {
		args = append(args, "-m", fmt.Sprintf("%d", perfTest.MsgSize))
	}
	exec := buildExecCommand(test, sip, perfTest.Duration, args)

	if streams >= 2 {
		exec = []string{"/bin/bash", "-c",
			// We write the output of each process to a separate file and cat them
			// at the end to prevent the possibility of interleaved output.
			fmt.Sprintf("DIR=$(mktemp -d); for i in {1..%d}; do %s > $DIR/out$i.out & done; wait; cat $DIR/*; rm -rf $DIR",
				streams, strings.Join(exec, " "),
			)}
	}

	a.ExecInPod(ctx, exec)
	output := a.CmdOutput()
	a.Debugf("Netperf output: %s", output)
	lines := slices.DeleteFunc(
		strings.Split(output, "\n"),
		// Result lines always start with a number, hence drop all the others.
		func(line string) bool { return len(line) == 0 || line[0] < '0' || line[0] > '9' },
	)
	if uint(len(lines)) != streams {
		a.Fatalf("Unable to process netperf result: expected %d, got %d", streams, len(lines))
	}

	res := parseNetperfResult(a, test, lines[0])
	for _, line := range lines[1:] {
		parsed := parseNetperfResult(a, test, line)
		res.ThroughputMetric.Throughput += parsed.ThroughputMetric.Throughput
	}

	return res
}
