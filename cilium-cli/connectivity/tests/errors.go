// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"

	"github.com/blang/semver/v4"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/cilium-cli/k8s"
	"github.com/cilium/cilium/cilium-cli/sysdump"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type logMatcher interface {
	IsMatch(log string) bool
}

type stringMatcher string

func (s stringMatcher) IsMatch(log string) bool {
	return strings.Contains(log, string(s))
}

type regexMatcher struct {
	*regexp.Regexp
}

func (r regexMatcher) IsMatch(log string) bool {
	return r.Regexp.MatchString(log)
}

// NoErrorsInLogs checks whether there are no error messages in cilium-agent
// logs. The error messages are defined in badLogMsgsWithExceptions, which key
// is an error message, while values is a list of ignored messages.
func NoErrorsInLogs(ciliumVersion semver.Version, checkLevels []string, externalTarget string, externalOtherTarget string) check.Scenario {
	// Exceptions for level=error should only be added as a last resort, if the
	// error cannot be fixed in Cilium or in the test.
	errorLogExceptions := []logMatcher{
		stringMatcher("Error in delegate stream, restarting"),
		failedToUpdateLock, failedToReleaseLock,
		failedToListCRDs, removeInexistentID, knownIssueWireguardCollision, nilDetailsForService}
	if ciliumVersion.LT(semver.MustParse("1.14.0")) {
		errorLogExceptions = append(errorLogExceptions, previouslyUsedCIDR, klogLeaderElectionFail)
	}

	envoyExternalTargetTLSWarning := regexMatcher{regexp.MustCompile(fmt.Sprintf(envoyTLSWarningTemplate, externalTarget))}
	envoyExternalOtherTargetTLSWarning := regexMatcher{regexp.MustCompile(fmt.Sprintf(envoyTLSWarningTemplate, externalOtherTarget))}
	warningLogExceptions := []logMatcher{cantEnableJIT, delMissingService, podCIDRUnavailable,
		unableGetNode, sessionAffinitySocketLB, objectHasBeenModified, noBackendResponse,
		legacyBGPFeature, etcdTimeout, endpointRestoreFailed, unableRestoreRouterIP,
		routerIPReallocated, cantFindIdentityInCache, keyAllocFailedFoundMaster,
		cantRecreateMasterKey, cantUpdateCRDIdentity, cantDeleteFromPolicyMap, failedToListCRDs,
		hubbleQueueFull, reflectPanic, svcNotFound, unableTranslateCIDRgroups, gobgpWarnings,
		endpointMapDeleteFailed, etcdReconnection, epRestoreMissingState, mutationDetectorKlog,
		hubbleFailedCreatePeer, fqdnDpUpdatesTimeout, longNetpolUpdate, failedToGetEpLabels,
		failedCreategRPCClient, unableReallocateIngressIP, fqdnMaxIPPerHostname, failedGetMetricsAPI,
		envoyExternalTargetTLSWarning, envoyExternalOtherTargetTLSWarning, ciliumNodeConfigDeprecation,
		hubbleUIEnvVarFallback, k8sClientNetworkStatusError, bgpAlphaResourceDeprecation, ccgAlphaResourceDeprecation,
		k8sEndpointDeprecatedWarn, proxylibDeprecatedWarn}
	// The list is adopted from cilium/cilium/test/helper/utils.go
	var errorMsgsWithExceptions = map[string][]logMatcher{
		panicMessage:         nil,
		deadLockHeader:       nil,
		RunInitFailed:        nil,
		emptyBPFInitArg:      nil,
		RemovingMapMsg:       {stringMatcher("globals/cilium_policy")},
		symbolSubstitution:   nil,
		uninitializedRegen:   nil,
		unstableStat:         nil,
		missingIptablesWait:  nil,
		localIDRestoreFail:   nil,
		routerIPMismatch:     nil,
		emptyIPNodeIDAlloc:   nil,
		"DATA RACE":          nil,
		envoyErrorMessage:    nil,
		envoyCriticalMessage: nil,
		// Slog's badkey
		"!BADKEY": nil,
	}
	if slices.Contains(checkLevels, defaults.LogLevelError) {
		errorMsgsWithExceptions["level=error"] = errorLogExceptions
	}
	if slices.Contains(checkLevels, defaults.LogLevelWarning) && ciliumVersion.GE(semver.MustParse("1.17.0")) {
		errorMsgsWithExceptions["level=warn"] = warningLogExceptions
	}
	return &noErrorsInLogs{
		errorMsgsWithExceptions: errorMsgsWithExceptions,
		ScenarioBase:            check.NewScenarioBase(),
		ciliumVersion:           ciliumVersion,
	}
}

type noErrorsInLogs struct {
	check.ScenarioBase

	errorMsgsWithExceptions map[string][]logMatcher
	ciliumVersion           semver.Version
	mostCommonFailureLog    string
	mostCommonFailureCount  int
}

func (n *noErrorsInLogs) FilePath() string {
	extractedPath := extractPathFromLog(n.mostCommonFailureLog)
	if extractedPath != "" {
		return extractedPath
	}
	// In case log did not contain the path,
	// we return the path of the test file.
	return n.ScenarioBase.FilePath()
}

func (n *noErrorsInLogs) Name() string {
	result := "no-errors-in-logs"
	extractedPath := extractPackageFromLog(n.mostCommonFailureLog)
	if extractedPath != "" {
		result = result + ":" + extractedPath
	}

	return result
}

type podID struct{ Cluster, Namespace, Name string }
type podContainers map[string]uint // Map container name to restart count
type podInfo struct {
	containers podContainers
	client     *k8s.Client
}

func (n *noErrorsInLogs) Run(ctx context.Context, t *check.Test) {
	pods, err := n.allCiliumPods(ctx, t.Context())
	if err != nil {
		t.Fatalf("Error retrieving Cilium pods: %s", err)
	}

	opts := corev1.PodLogOptions{LimitBytes: ptr.To[int64](sysdump.DefaultLogsLimitBytes)}
	prevOpts := opts
	prevOpts.Previous = true
	for pod, info := range pods {
		client := info.client
		for container, restarts := range info.containers {
			id := fmt.Sprintf("%s/%s/%s (%s)", pod.Cluster, pod.Namespace, pod.Name, container)
			t.NewGenericAction(n, id).Run(func(a *check.Action) {
				// Do not check for container restarts for Cilium v1.16 and earlier.
				ignore := n.ciliumVersion.LT(semver.MustParse("1.17.0"))

				// Ignore Cilium operator restarts for the moment, as they can
				// legitimately happen in case it loses the leader election due
				// to temporary control plane blips.
				ignore = ignore || container == "cilium-operator"

				// The hubble relay container can currently be restarted by the
				// startup probe if it fails to connect to Cilium. However, this
				// can legitimately happen when the certificates are generated
				// for the first time, as that they then need to be reloaded
				// by the agents. Given that we cannot configure the settings of
				// the startup probe, let's just accept one possible restart here.
				ignore = ignore || (restarts == 1 && container == "hubble-relay")

				var logs bytes.Buffer
				err := client.GetLogs(ctx, pod.Namespace, pod.Name, container, opts, &logs)
				if err != nil {
					a.Fatalf("Error reading Cilium logs: %s", err)
				}
				n.checkErrorsInLogs(id, logs.Bytes(), a, &opts)

				if restarts > 0 && !ignore {
					a.Failf("Non-zero (%d) restart count of %s must be investigated", restarts, id)

					logs = bytes.Buffer{}
					err := client.GetLogs(ctx, pod.Namespace, pod.Name, container, prevOpts, &logs)
					if err == nil {
						n.checkErrorsInLogs(id, logs.Bytes(), a, &prevOpts)
					} else {
						a.Failf("Error reading Cilium logs: %s", err)
					}
				}
			})
		}
	}

}

// NoUnexpectedPacketDrops checks whether there were no drops due to expected
// packet drops.
func NoUnexpectedPacketDrops(expectedDrops []string) check.Scenario {
	return &noUnexpectedPacketDrops{
		expectedDrops: expectedDrops,
		ScenarioBase:  check.NewScenarioBase(),
	}
}

type noUnexpectedPacketDrops struct {
	check.ScenarioBase

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
		t.NewGenericAction(n, fmt.Sprintf("%s/%s", pod.K8sClient.ClusterName(), pod.NodeName())).Run(func(a *check.Action) {
			stdout, err := pod.K8sClient.ExecInPod(ctx, pod.Pod.Namespace, pod.Pod.Name, defaults.AgentContainerName, cmd)
			if err != nil {
				a.Fatalf("Error fetching packet drop counts: %s", err)
			}
			countStr := strings.TrimSpace(stdout.String())
			if countStr != "" {
				a.Failf("Found unexpected packet drops:\n%s", countStr)
			}
		})
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

func (n *noErrorsInLogs) allCiliumPods(ctx context.Context, ct *check.ConnectivityTest) (map[podID]podInfo, error) {
	output := make(map[podID]podInfo)

	// List all Cilium-related pods
	for _, client := range ct.Clients() {
		pods, err := client.ListPods(ctx, ct.Params().CiliumNamespace, metav1.ListOptions{LabelSelector: ct.Params().CiliumPodSelector})
		if err != nil {
			return nil, err
		}

		cluster := client.ClusterName()
		for _, pod := range pods.Items {
			output[podID{Cluster: cluster, Namespace: pod.Namespace, Name: pod.Name}] = podInfo{
				client: client, containers: n.podContainers(&pod),
			}
		}
	}

	// Additionally add Cilium agent pods, if not already included in the previous
	// list. This prevents missing them in case the "all cilium pods" selector does
	// not match any pod (mainly in v1.12, as the app.kubernetes.io/part-of=cilium
	// label was not yet present at that time).
	for _, pod := range ct.CiliumPods() {
		id := podID{Cluster: pod.K8sClient.ClusterName(), Namespace: pod.Namespace(), Name: pod.NameWithoutNamespace()}
		if _, ok := output[id]; !ok {
			output[id] = podInfo{client: pod.K8sClient, containers: n.podContainers(pod.Pod)}
		}
	}

	return output, nil
}

func (n *noErrorsInLogs) podContainers(pod *corev1.Pod) podContainers {
	restarts := func(statuses []corev1.ContainerStatus, name string) (restarts uint) {
		for _, status := range statuses {
			if status.Name == name {
				return uint(status.RestartCount)
			}
		}
		return 0
	}

	containers := make(podContainers, len(pod.Spec.Containers)+len(pod.Spec.InitContainers))

	for _, container := range pod.Spec.Containers {
		containers[container.Name] = restarts(pod.Status.ContainerStatuses, container.Name)
	}

	for _, container := range pod.Spec.InitContainers {
		containers[container.Name] = restarts(pod.Status.InitContainerStatuses, container.Name)
	}

	return containers
}

func (n *noErrorsInLogs) findUniqueFailures(logs []byte) (map[string]int, map[string]string) {
	uniqueFailures := make(map[string]int)
	exampleLogLine := make(map[string]string)
	for chunk := range bytes.SplitSeq(logs, []byte("\n")) {
		msg := string(chunk)
		for fail, ignoreMsgs := range n.errorMsgsWithExceptions {
			if strings.Contains(msg, fail) {
				ok := false
				for _, ignore := range ignoreMsgs {
					if ignore.IsMatch(msg) {
						ok = true
						break
					}
				}
				if !ok {
					justMsg := extractValueFromLog(msg, "msg")
					if justMsg == "" {
						// Matching didn't work, fallback to previous behaviour
						justMsg = msg
					}
					count := uniqueFailures[justMsg]
					uniqueFailures[justMsg] = count + 1
					exampleLogLine[justMsg] = msg
				}
			}
		}
	}
	for f, c := range uniqueFailures {
		if c > n.mostCommonFailureCount {
			n.mostCommonFailureCount = c
			n.mostCommonFailureLog = exampleLogLine[f]
		}
	}
	return uniqueFailures, exampleLogLine
}

func extractValueFromLog(log string, key string) string {
	// Capture key="something" or key=something
	pattern := fmt.Sprintf(`\b%s=("[^"]*"|[^\s]*)`, key)
	re, err := regexp.Compile(pattern)
	if err != nil {
		return ""
	}
	matches := re.FindStringSubmatch(log)
	if len(matches) > 1 {
		return strings.Trim(matches[1], `"`)
	}
	return ""
}

func extractPathFromLog(log string) string {
	source := extractValueFromLog(log, "source")
	parts := strings.Split(source, ":")
	if len(parts) < 2 {
		return ""
	}
	source = strings.Split(source, ":")[0]
	_, thisPath, _, _ := runtime.Caller(0)
	repoDir, _ := filepath.Abs(filepath.Join(thisPath, "..", "..", "..", ".."))
	// We trim twice for cases when cilium and cilium-cli are built in a different ways.
	// For example, when cilium is built with make kind-image in Docker, but cilium-cli is built
	// on the local host.
	result := strings.TrimPrefix(source, repoDir+string(filepath.Separator))
	return strings.TrimPrefix(result, "/go/src/github.com/cilium/cilium/")
}

func extractPackageFromLog(log string) string {
	result := extractPathFromLog(log)
	if result == "" {
		return ""
	}
	result, _ = filepath.Split(result)
	return filepath.Clean(result)
}

func (n *noErrorsInLogs) checkErrorsInLogs(id string, logs []byte, a *check.Action, opts *corev1.PodLogOptions) {
	uniqueFailures, exampleLogLine := n.findUniqueFailures(logs)
	if len(uniqueFailures) > 0 {
		var failures strings.Builder
		for f, c := range uniqueFailures {
			failures.WriteRune('\n')
			failures.WriteString(exampleLogLine[f])
			failures.WriteString(fmt.Sprintf(" (%d occurrences)", c))

		}
		previous := ""
		if opts.Previous {
			previous = " from before pod restart"
		}
		a.Failf("Found %d logs in %s%s matching list of errors that must be investigated:%s", len(uniqueFailures), id, previous, failures.String())
	}
}

const (
	// Logs messages that should not be in the cilium logs
	panicMessage                         = "panic:"
	deadLockHeader                       = "POTENTIAL DEADLOCK:"                                  // from github.com/sasha-s/go-deadlock/deadlock.go:header
	RunInitFailed                        = "JoinEP: "                                             // from https://github.com/cilium/cilium/pull/5052
	emptyBPFInitArg                      = "empty argument passed to bpf/init.sh"                 // from https://github.com/cilium/cilium/issues/10228
	RemovingMapMsg                       = "Removing map to allow for property upgrade"           // from https://github.com/cilium/cilium/pull/10626
	symbolSubstitution                   = "Skipping symbol substitution"                         //
	uninitializedRegen                   = "Uninitialized regeneration level"                     // from https://github.com/cilium/cilium/pull/10949
	unstableStat                         = "BUG: stat() has unstable behavior"                    // from https://github.com/cilium/cilium/pull/11028
	removeInexistentID     stringMatcher = "removing identity not added to the identity manager!" // from https://github.com/cilium/cilium/issues/16419
	missingIptablesWait                  = "Missing iptables wait arg (-w):"
	localIDRestoreFail                   = "Could not restore all CIDR identities" // from https://github.com/cilium/cilium/pull/19556
	routerIPMismatch                     = "Mismatch of router IPs found during restoration"
	emptyIPNodeIDAlloc                   = "Attempt to allocate a node ID for an empty node IP address"
	failedToListCRDs       stringMatcher = "the server could not find the requested resource" // cf. https://github.com/cilium/cilium/issues/16425
	failedToUpdateLock     stringMatcher = "Failed to update lock:"
	failedToReleaseLock    stringMatcher = "Failed to release lock:"
	previouslyUsedCIDR     stringMatcher = "Unable to find identity of previously used CIDR"                           // from https://github.com/cilium/cilium/issues/26881
	klogLeaderElectionFail stringMatcher = "error retrieving resource lock kube-system/cilium-operator-resource-lock:" // from: https://github.com/cilium/cilium/issues/31050
	nilDetailsForService   stringMatcher = "retrieved nil details for Service"                                         // from: https://github.com/cilium/cilium/issues/35595

	cantEnableJIT               stringMatcher = "bpf_jit_enable: no such file or directory"                              // Because we run tests in Kind.
	delMissingService           stringMatcher = "Deleting no longer present service"                                     // cf. https://github.com/cilium/cilium/issues/29679
	podCIDRUnavailable          stringMatcher = " PodCIDR not available"                                                 // cf. https://github.com/cilium/cilium/issues/29680
	unableGetNode               stringMatcher = "Unable to get node resource"                                            // cf. https://github.com/cilium/cilium/issues/29710
	sessionAffinitySocketLB     stringMatcher = "Session affinity for host reachable services needs kernel"              // cf. https://github.com/cilium/cilium/issues/29736
	objectHasBeenModified       stringMatcher = "the object has been modified; please apply your changes"                // cf. https://github.com/cilium/cilium/issues/29712
	noBackendResponse           stringMatcher = "The kernel does not support --service-no-backend-response=reject"       // cf. https://github.com/cilium/cilium/issues/29733
	legacyBGPFeature            stringMatcher = "You are using the legacy BGP feature"                                   // Expected when testing the legacy BGP feature.
	etcdTimeout                 stringMatcher = "etcd client timeout exceeded"                                           // cf. https://github.com/cilium/cilium/issues/29714
	endpointRestoreFailed       stringMatcher = "Unable to restore endpoint, ignoring"                                   // cf. https://github.com/cilium/cilium/issues/29716
	unableRestoreRouterIP       stringMatcher = "Unable to restore router IP from filesystem"                            // cf. https://github.com/cilium/cilium/issues/29715
	routerIPReallocated         stringMatcher = "Router IP could not be re-allocated"                                    // cf. https://github.com/cilium/cilium/issues/29715
	cantFindIdentityInCache     stringMatcher = "unable to release identity: unable to find key in local cache"          // cf. https://github.com/cilium/cilium/issues/29732
	keyAllocFailedFoundMaster   stringMatcher = "Found master key after proceeding with new allocation"                  // cf. https://github.com/cilium/cilium/issues/29738
	cantRecreateMasterKey       stringMatcher = "unable to re-create missing master key"                                 // cf. https://github.com/cilium/cilium/issues/29738
	cantUpdateCRDIdentity       stringMatcher = "Unable update CRD identity information with a reference for this node"  // cf. https://github.com/cilium/cilium/issues/29739
	cantDeleteFromPolicyMap     stringMatcher = "cilium_call_policy: delete: key does not exist"                         // cf. https://github.com/cilium/cilium/issues/29754
	hubbleQueueFull             stringMatcher = "hubble events queue is full"                                            // Because we run without monitor aggregation
	reflectPanic                stringMatcher = "reflect.Value.SetUint using value obtained using unexported field"      // cf. https://github.com/cilium/cilium/issues/33766
	svcNotFound                 stringMatcher = "service not found"                                                      // cf. https://github.com/cilium/cilium/issues/35768
	unableTranslateCIDRgroups   stringMatcher = "Unable to translate all CIDR groups to CIDRs"                           // Can be removed once v1.17 is released.
	gobgpWarnings               stringMatcher = "component=gobgp.BgpServerInstance"                                      // cf. https://github.com/cilium/cilium/issues/35799
	etcdReconnection            stringMatcher = "Error observed on etcd connection, reconnecting etcd"                   // cf. https://github.com/cilium/cilium/issues/35865
	epRestoreMissingState       stringMatcher = "Couldn't find state, ignoring endpoint"                                 // cf. https://github.com/cilium/cilium/issues/35869
	mutationDetectorKlog        stringMatcher = "Mutation detector is enabled, this will result in memory leakage."      // cf. https://github.com/cilium/cilium/issues/35929
	hubbleFailedCreatePeer      stringMatcher = "Failed to create peer client for peers synchronization"                 // cf. https://github.com/cilium/cilium/issues/35930
	fqdnDpUpdatesTimeout        stringMatcher = "Timed out waiting for datapath updates of FQDN IP information"          // cf. https://github.com/cilium/cilium/issues/35931
	longNetpolUpdate            stringMatcher = "onConfigUpdate(): Worker threads took longer than"                      // cf. https://github.com/cilium/cilium/issues/36067
	failedToGetEpLabels         stringMatcher = "Failed to get identity labels for endpoint"                             // cf. https://github.com/cilium/cilium/issues/36068
	failedCreategRPCClient      stringMatcher = "Failed to create gRPC client"                                           // cf. https://github.com/cilium/cilium/issues/36070
	unableReallocateIngressIP   stringMatcher = "unable to re-allocate ingress IPv6"                                     // cf. https://github.com/cilium/cilium/issues/36072
	fqdnMaxIPPerHostname        stringMatcher = "Raise tofqdns-endpoint-max-ip-per-hostname to mitigate this"            // cf. https://github.com/cilium/cilium/issues/36073
	failedGetMetricsAPI         stringMatcher = "retrieve the complete list of server APIs: metrics.k8s.io/v1beta1"      // cf. https://github.com/cilium/cilium/issues/36085
	ciliumNodeConfigDeprecation stringMatcher = "cilium.io/v2alpha1 CiliumNodeConfig will be deprecated in cilium v1.16" // cf. https://github.com/cilium/cilium/issues/37249
	hubbleUIEnvVarFallback      stringMatcher = "using fallback value for env var"                                       // cf. https://github.com/cilium/hubble-ui/pull/940
	k8sClientNetworkStatusError stringMatcher = "Network status error received, restarting client connections"           // cf. https://github.com/cilium/cilium/issues/37712

	k8sEndpointDeprecatedWarn stringMatcher = "v1 Endpoints is deprecated in v1.33+; use discovery.k8s.io/v1 EndpointSlice" // cf. https://github.com/cilium/cilium/issues/39105
	proxylibDeprecatedWarn    stringMatcher = "The support for Envoy Go Extensions (proxylib) has been deprecated"          // cf. https://github.com/cilium/cilium/issues/38224

	// Logs messages that should not be in the cilium-envoy DS logs
	envoyErrorMessage    = "[error]"
	envoyCriticalMessage = "[critical]"
)

var (
	// knownBugWireguardCollision is for a known issue: https://github.com/cilium/cilium/issues/31535.
	// In spite of this occurrence, fqdn connectivity tests still pass thus it should be ok to ignore these for a while
	// while we fix this issue.
	// TODO: Remove this after: #31535 has been fixed.
	knownIssueWireguardCollision = regexMatcher{regexp.MustCompile("Cannot forward proxied DNS lookup.*:51871.*bind: address already in use")} // from: https://github.com/cilium/cilium/issues/30901
	// Cf. https://github.com/cilium/cilium/issues/35803
	endpointMapDeleteFailed = regexMatcher{regexp.MustCompile(`Ignoring error while deleting endpoint.*from map cilium_\w+: delete: key does not exist`)}
	// envoyTLSWarningTemplate is the legitimate warning log for negative TLS SNI test case
	// This is a template string as we need to replace %s for external target flag
	envoyTLSWarningTemplate = "cilium.tls_wrapper: Could not get server TLS context for pod.*on destination IP.*port 443 sni.*%s.*and raw socket is not allowed"
	// bgpV2alpha1ResourceDeprecation is expected when using deprecated BGP resource versions in a test, specifically when running the tests after a Cilium downgrade.
	bgpAlphaResourceDeprecation = regexMatcher{regexp.MustCompile(`cilium.io/v2alpha1 CiliumBGP\w+ is deprecated`)}
	// ccgAlphaResourceDeprecation is the same as bgpAlphaResourceDeprecation but for the CiliumCIDRGroup.
	ccgAlphaResourceDeprecation = regexMatcher{regexp.MustCompile(`cilium.io/v2alpha1 CiliumCIDRGroup is deprecated`)}
)
