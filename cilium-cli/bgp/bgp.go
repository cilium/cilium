// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bgp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/blang/semver/v4"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/cilium-cli/k8s"
)

// output format of BGP hive shell commands
type tableJSON struct {
	Columns []string            `json:"columns"`
	Rows    []map[string]string `json:"rows"`
}

func (t tableJSON) ToStrings() []string {
	rows := []string{strings.Join(t.Columns, "\t")}
	for _, row := range t.Rows {
		var builder strings.Builder
		for j, column := range t.Columns {
			if j != 0 {
				builder.WriteString("\t")
			}
			builder.WriteString(row[column])
		}
		rows = append(rows, builder.String())
	}

	return rows
}

// Parameters contains options for CLI
type Parameters struct {
	CiliumNamespace  string
	AgentPodSelector string
	NodeName         string
	Writer           io.Writer
	WaitDuration     time.Duration
	Output           string
	ShowCaps         bool
	ShowAttrs        bool
}

// Status is used to get bgp state from cilium agents
type Status struct {
	client     *k8s.Client
	params     Parameters
	ciliumPods []*corev1.Pod
}

// NewStatus returns new bgp.Status struct
func NewStatus(client *k8s.Client, p Parameters) *Status {
	return &Status{
		client: client,
		params: p,
	}
}

// initTargetCiliumPods stores cilium agent pods in the status.ciliumPods.
// If node selector option is specified then only that nodes' cilium-agent
// pod is stored else all cilium-agents in the cluster are stored.
func (s *Status) initTargetCiliumPods(ctx context.Context) error {
	opts := metav1.ListOptions{LabelSelector: s.params.AgentPodSelector}
	if s.params.NodeName != "" {
		opts.FieldSelector = fmt.Sprintf("spec.nodeName=%s", s.params.NodeName)
	}

	ciliumPods, err := s.client.ListPods(ctx, s.params.CiliumNamespace, opts)
	if err != nil {
		return fmt.Errorf("unable to list Cilium pods: %w", err)
	}

	for _, ciliumPod := range ciliumPods.Items {
		s.ciliumPods = append(s.ciliumPods, ciliumPod.DeepCopy())
	}
	return nil
}

// checkCiliumVersion checks if the cilium agent version is supported.
func (s *Status) checkCiliumVersion(ctx context.Context, pod *corev1.Pod) error {
	version := make(map[string]map[string]string)
	cmd := []string{"cilium-dbg", "version", "-o", "json"}
	output, err := s.client.ExecInPod(ctx, pod.Namespace, pod.Name, defaults.AgentContainerName, cmd)
	if err != nil {
		return fmt.Errorf("failed to get Cilium version: %w", err)
	}
	if err := json.Unmarshal(output.Bytes(), &version); err != nil {
		return fmt.Errorf("failed to get Cilium version: %w", err)
	}

	actualVersion, err := semver.Parse(version["Client"]["Version"])
	if err != nil {
		return fmt.Errorf("failed to get Cilium version: %w", err)
	}
	if isLegacyCiliumVersion(actualVersion) {
		return fmt.Errorf("Cilium version <1.20.0 does not support this command")
	}

	return nil
}

// isLegacyCiliumVersion return true if the version is <1.20.0-pre.3 or not 1.20.0-dev
func isLegacyCiliumVersion(actualVersion semver.Version) bool {
	supportedRange := semver.MustParseRange(">=1.20.0-pre.3")
	return !(supportedRange(actualVersion) || actualVersion.EQ(semver.MustParse("1.20.0-dev")))
}

// fetchCmdFromPod defines the function signature for running a fetch command on the pods.
type fetchCmdFromPod func(context.Context, []string, *corev1.Pod) ([]string, error)

func (s *Status) fetchCmdConcurrently(ctx context.Context, fetchCmd []string, fetchFunc fetchCmdFromPod) (map[string][]string, error) {
	allFetchedData := make(map[string][]string)

	// res contains data returned from cilium pod
	type res struct {
		nodeName string
		data     []string
		err      error
	}
	resCh := make(chan res)

	var wg sync.WaitGroup

	// max number of concurrent go routines will be number of cilium agent pods
	wg.Add(len(s.ciliumPods))

	// concurrently fetch routes from each cilium pod
	for _, pod := range s.ciliumPods {
		go func(ctx context.Context, pod *corev1.Pod) {
			defer wg.Done()

			routes, err := fetchFunc(ctx, fetchCmd, pod)
			resCh <- res{
				nodeName: pod.Spec.NodeName,
				data:     routes,
				err:      err,
			}
		}(ctx, pod)
	}

	// close resCh when data from all nodes is collected
	go func() {
		wg.Wait()
		close(resCh)
	}()

	// read from the channel till it is closed.
	// on error, store error and continue to next node.
	var err error
	for fetchedData := range resCh {
		if fetchedData.err != nil {
			err = errors.Join(err, fetchedData.err)
		} else {
			allFetchedData[fetchedData.nodeName] = fetchedData.data
		}
	}

	return allFetchedData, err
}
