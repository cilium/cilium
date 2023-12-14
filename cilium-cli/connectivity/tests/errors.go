// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/blang/semver/v4"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/utils/features"
)

// NoErrorsInLogs checks whether there are no error messages in cilium-agent
// logs. The error messages are defined in badLogMsgsWithExceptions, which key
// is an error message, while values is a list of ignored messages.
func NoErrorsInLogs(ciliumVersion semver.Version) check.Scenario {
	// Exceptions for level=error should only be added as a last resort, if the
	// error cannot be fixed in Cilium or in the test.
	errorLogExceptions := []string{"Error in delegate stream, restarting", failedToListCRDs, removeInexistentID}
	if ciliumVersion.LT(semver.MustParse("1.14.0")) {
		errorLogExceptions = append(errorLogExceptions, previouslyUsedCIDR)
	}
	// The list is adopted from cilium/cilium/test/helper/utils.go
	var errorMsgsWithExceptions = map[string][]string{
		panicMessage:        nil,
		deadLockHeader:      nil,
		segmentationFault:   nil,
		NACKreceived:        nil,
		RunInitFailed:       nil,
		sizeMismatch:        {"globals/cilium_policy"},
		emptyBPFInitArg:     nil,
		RemovingMapMsg:      {"globals/cilium_policy"},
		logBufferMessage:    nil,
		ClangErrorsMsg:      nil,
		ClangErrorMsg:       nil,
		symbolSubstitution:  nil,
		uninitializedRegen:  nil,
		unstableStat:        nil,
		removeTransientRule: nil,
		missingIptablesWait: nil,
		localIDRestoreFail:  nil,
		routerIPMismatch:    nil,
		emptyIPNodeIDAlloc:  nil,
		"DATA RACE":         nil,
		"level=error":       errorLogExceptions,
	}
	return &noErrorsInLogs{errorMsgsWithExceptions}
}

type noErrorsInLogs struct {
	errorMsgsWithExceptions map[string][]string
}

func (n *noErrorsInLogs) Name() string {
	return "no-errors-in-logs"
}

func (n *noErrorsInLogs) Run(ctx context.Context, t *check.Test) {
	var since time.Time
	ct := t.Context()

	for _, pod := range ct.CiliumPods() {
		pod := pod
		logs, err := pod.K8sClient.CiliumLogs(ctx, pod.Pod.Namespace, pod.Pod.Name, since, nil)
		if err != nil {
			t.Fatalf("Error reading Cilium logs: %s", err)
		}
		n.checkErrorsInLogs(logs, t)
	}

}

// NoUnexpectedPacketDrops checks whether there were no drops due to expected
// packet drops.
func NoUnexpectedPacketDrops(expectedDrops []string) check.Scenario {
	return &noUnexpectedPacketDrops{expectedDrops}
}

type noUnexpectedPacketDrops struct {
	expectedDrops []string
}

func (n *noUnexpectedPacketDrops) Name() string {
	return "no-unexpected-packet-drops"
}

func (n *noUnexpectedPacketDrops) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()

	filter := computeExpectedDropReasons(defaults.ExpectedDropReasons, n.expectedDrops)
	cmd := []string{
		"/bin/sh", "-c",
		fmt.Sprintf("cilium metrics list -o json | jq '.[] | select((.name == \"cilium_drop_count_total\") and (.labels.reason | IN(%s) | not))'", filter),
	}

	for _, pod := range ct.CiliumPods() {
		pod := pod
		stdout, err := pod.K8sClient.ExecInPod(ctx, pod.Pod.Namespace, pod.Pod.Name, defaults.AgentContainerName, cmd)
		if err != nil {
			t.Fatalf("Error fetching packet drop counts: %s", err)
		}
		countStr := strings.TrimSpace(stdout.String())
		if countStr != "" {
			t.Fatalf("Found unexpected packet drops:\n%s", countStr)
		}
	}
}

func computeExpectedDropReasons(defaultReasons, inputReasons []string) string {
	filter := ""
	dropReasons := features.ComputeFailureExceptions(defaultReasons, inputReasons)

	if len(dropReasons) > 0 {
		// Build output string in form of '"reason1", "reason2"'.
		filter = fmt.Sprintf("%q", dropReasons[0])
		for _, reason := range dropReasons[1:] {
			filter = fmt.Sprintf("%s, %q", filter, reason)
		}
	}
	return filter
}

func (n *noErrorsInLogs) checkErrorsInLogs(logs string, t *check.Test) {
	uniqueFailures := make(map[string]int)
	for _, msg := range strings.Split(logs, "\n") {
		for fail, ignoreMsgs := range n.errorMsgsWithExceptions {
			if strings.Contains(msg, fail) {
				ok := false
				for _, ignore := range ignoreMsgs {
					if strings.Contains(msg, ignore) {
						ok = true
						break
					}
				}
				if !ok {
					count := uniqueFailures[msg]
					uniqueFailures[msg] = count + 1
				}
			}
		}
	}
	if len(uniqueFailures) > 0 {
		var failures strings.Builder
		for f, c := range uniqueFailures {
			failures.WriteRune('\n')
			failures.WriteString(f)
			failures.WriteString(fmt.Sprintf(" (%d occurrences)", c))
		}
		t.Failf("Found %d logs matching list of errors that must be investigated:%s", len(uniqueFailures), failures.String())
	}
}

const (
	// Logs messages that should not be in the cilium logs
	panicMessage        = "panic:"
	deadLockHeader      = "POTENTIAL DEADLOCK:"                                      // from github.com/sasha-s/go-deadlock/deadlock.go:header
	segmentationFault   = "segmentation fault"                                       // from https://github.com/cilium/cilium/issues/3233
	NACKreceived        = "NACK received for version"                                // from https://github.com/cilium/cilium/issues/4003
	RunInitFailed       = "JoinEP: "                                                 // from https://github.com/cilium/cilium/pull/5052
	sizeMismatch        = "size mismatch for BPF map"                                // from https://github.com/cilium/cilium/issues/7851
	emptyBPFInitArg     = "empty argument passed to bpf/init.sh"                     // from https://github.com/cilium/cilium/issues/10228
	RemovingMapMsg      = "Removing map to allow for property upgrade"               // from https://github.com/cilium/cilium/pull/10626
	logBufferMessage    = "Log buffer too small to dump verifier log"                // from https://github.com/cilium/cilium/issues/10517
	ClangErrorsMsg      = " errors generated."                                       // from https://github.com/cilium/cilium/issues/10857
	ClangErrorMsg       = "1 error generated."                                       // from https://github.com/cilium/cilium/issues/10857
	symbolSubstitution  = "Skipping symbol substitution"                             //
	uninitializedRegen  = "Uninitialized regeneration level"                         // from https://github.com/cilium/cilium/pull/10949
	unstableStat        = "BUG: stat() has unstable behavior"                        // from https://github.com/cilium/cilium/pull/11028
	removeTransientRule = "Unable to process chain CILIUM_TRANSIENT_FORWARD with ip" // from https://github.com/cilium/cilium/issues/11276
	removeInexistentID  = "removing identity not added to the identity manager!"     // from https://github.com/cilium/cilium/issues/16419
	missingIptablesWait = "Missing iptables wait arg (-w):"
	localIDRestoreFail  = "Could not restore all CIDR identities" // from https://github.com/cilium/cilium/pull/19556
	routerIPMismatch    = "Mismatch of router IPs found during restoration"
	emptyIPNodeIDAlloc  = "Attempt to allocate a node ID for an empty node IP address"
	failedToListCRDs    = "the server could not find the requested resource" // cf. https://github.com/cilium/cilium/issues/16425
	previouslyUsedCIDR  = "Unable to find identity of previously used CIDR"  // from https://github.com/cilium/cilium/issues/26881
)
