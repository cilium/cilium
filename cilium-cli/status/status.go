// Copyright 2020 Authors of Cilium
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

package status

import (
	"bytes"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/cilium/cilium/api/v1/models"
)

const (
	Red     = "\033[31m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Green   = "\033[32m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	Reset   = "\033[0m"
)

// MapCount is a map to count number of occurences of a string
type MapCount map[string]int

// MapMapCount is a map of MapCount indexed by string
type MapMapCount map[string]MapCount

// PodStateCount counts the number of pods in a particular state
type PodStateCount struct {
	// Type is the type of deployment ("Deployment", "DaemonSet", ...)
	Type string

	// Desired is the number of desired pods to be scheduled
	Desired int

	// Ready is the number of ready pods
	Ready int

	// Available is the number of available pods
	Available int

	// Unavailable is the number of unavailable pods
	Unavailable int
}

type PodStateMap map[string]PodStateCount

type CiliumStatusMap map[string]*models.StatusResponse

type ErrorCount struct {
	Errors   []error
	Warnings []error
}

type ErrorCountMap map[string]*ErrorCount

type ErrorCountMapMap map[string]ErrorCountMap

// Status is the overall status of Cilium
type Status struct {
	// ImageCount is a map counting the number of images in use indexed by
	// the image name
	ImageCount MapMapCount

	// PhaseCount is a map counting the number of pods in each phase
	// (running, failing, scheduled, ...)
	PhaseCount MapMapCount

	// PodState counts the number of pods matching conditions such as
	// desired, ready, available, and unavailable
	PodState PodStateMap

	CiliumStatus CiliumStatusMap

	// Errors is the aggregated errors and warnings of all pods of a
	// particular deployment type
	Errors ErrorCountMapMap

	// CollectionErrors is the errors that accumulated while collecting the
	// status
	CollectionErrors []error
}

func newStatus() *Status {
	return &Status{
		ImageCount:   MapMapCount{},
		PhaseCount:   MapMapCount{},
		PodState:     PodStateMap{},
		CiliumStatus: CiliumStatusMap{},
		Errors:       ErrorCountMapMap{},
	}
}

func (s *Status) aggregatedErrorCount(deployment, pod string) *ErrorCount {
	m := s.Errors[deployment]
	if m == nil {
		m = ErrorCountMap{}
		s.Errors[deployment] = m
	}

	if m[pod] == nil {
		m[pod] = &ErrorCount{}
	}

	return m[pod]
}

func (s *Status) AddAggregatedError(deployment, pod string, err error) {
	m := s.aggregatedErrorCount(deployment, pod)
	m.Errors = append(m.Errors, err)
}

func (s *Status) AddAggregatedWarning(deployment, pod string, warning error) {
	m := s.aggregatedErrorCount(deployment, pod)
	m.Warnings = append(m.Warnings, warning)
}

func (s *Status) CollectionError(err error) {
	s.CollectionErrors = append(s.CollectionErrors, err)
}

func (s *Status) parseCiliumSubsystemState(deployment, podName, subsystem, state, msg string) {
	switch strings.ToLower(state) {
	case "warning":
		s.AddAggregatedWarning(deployment, podName, fmt.Errorf("%s: %s", subsystem, msg))
	case "failure":
		s.AddAggregatedError(deployment, podName, fmt.Errorf("%s: %s", subsystem, msg))
	}
}

func (s *Status) parseCiliumSubsystemStatus(deployment, podName, subsystem string, status *models.Status) {
	if status != nil {
		s.parseCiliumSubsystemState(deployment, podName, subsystem, status.State, status.Msg)
	}
}

func (s *Status) parseStatusResponse(deployment, podName string, r *models.StatusResponse, err error) {
	if err != nil {
		s.AddAggregatedError(deployment, podName, fmt.Errorf("unable to retrieve cilium status: %s", err))
		return
	}

	if r.Cilium != nil {
		s.parseCiliumSubsystemStatus(deployment, podName, "Cilium", r.Cilium)
	}

	if r.Cluster != nil {
		s.parseCiliumSubsystemStatus(deployment, podName, "Health", r.Cluster.CiliumHealth)
	}

	if r.Hubble != nil {
		s.parseCiliumSubsystemState(deployment, podName, "Hubble", r.Hubble.State, r.Hubble.Msg)
	}

	if r.Kubernetes != nil {
		s.parseCiliumSubsystemState(deployment, podName, "Kubernetes", r.Kubernetes.State, r.Kubernetes.Msg)
	}

	if r.Kvstore != nil {
		s.parseCiliumSubsystemStatus(deployment, podName, "Kvstore", r.Kvstore)
	}

	if len(r.Controllers) > 0 {
		for _, ctrl := range r.Controllers {
			if ctrl.Status == nil || ctrl.Status.ConsecutiveFailureCount == 0 {
				continue
			}

			s.AddAggregatedError(deployment, podName, fmt.Errorf("Controller %s is failing since %s (%dx): %s",
				ctrl.Name,
				time.Since(time.Time(ctrl.Status.LastFailureTimestamp)).Truncate(time.Second).String(),
				ctrl.Status.ConsecutiveFailureCount,
				ctrl.Status.LastFailureMsg))
		}
	}

	return
}

func (s *Status) statusSummary(name string) (text string) {
	var errors, warnings int
	if a := s.Errors[name]; a != nil {
		for _, c := range a {
			errors += len(c.Errors)
			warnings += len(c.Warnings)
		}

		if errors > 0 {
			text += Red + fmt.Sprintf("%d errors", errors) + Reset
		}

		if warnings > 0 {
			if text != "" {
				text += ", "
			}
			text += Yellow + fmt.Sprintf("%d warnings", warnings) + Reset
		}
	}
	if text == "" {
		text = Green + "OK" + Reset
	}

	return
}

func formatPhaseCount(m MapCount) string {
	var items []string
	for phase, count := range m {
		color := ""
		switch phase {
		case "Failed", "Unknown":
			color = Red
		case "Running", "Pending", "Succeeded":
			color = Green
		}

		items = append(items, fmt.Sprintf("%s: "+color+"%d"+Reset, phase, count))
	}
	return strings.Join(items, ", ")
}

func (c PodStateCount) Format() string {
	var items []string

	if c.Desired > 0 {
		items = append(items, fmt.Sprintf("Desired: %d", c.Desired))
	}

	if c.Ready > 0 {
		color := Green
		if c.Ready < c.Desired {
			color = Yellow
		}
		items = append(items, fmt.Sprintf("Ready: "+color+"%d/%d"+Reset, c.Ready, c.Desired))
	}

	if c.Available > 0 {
		color := Green
		if c.Ready < c.Desired {
			color = Yellow
		}
		items = append(items, fmt.Sprintf("Available: "+color+"%d/%d"+Reset, c.Available, c.Desired))
	}

	if c.Unavailable > 0 {
		items = append(items, fmt.Sprintf("Unavailable: "+Red+"%d/%d"+Reset, c.Unavailable, c.Desired))
	}

	return strings.Join(items, ", ")
}

func (s *Status) Format() string {
	var buf bytes.Buffer

	w := tabwriter.NewWriter(&buf, 0, 0, 4, ' ', 0)

	fmt.Fprintf(w, Yellow+"    /¯¯\\\n")
	fmt.Fprintf(w, Cyan+" /¯¯"+Yellow+"\\__/"+Green+"¯¯\\"+Reset+"\tCilium:\t"+s.statusSummary(ciliumDaemonSetName)+"\n")
	fmt.Fprintf(w, Cyan+" \\__"+Red+"/¯¯\\"+Green+"__/"+Reset+"\tOperator:\t"+s.statusSummary(operatorDeploymentName)+"\n")
	fmt.Fprintf(w, Green+" /¯¯"+Red+"\\__/"+Magenta+"¯¯\\"+Reset+"\tHubble:\t"+s.statusSummary(relayDeploymentName)+"\n")
	fmt.Fprintf(w, Green+" \\__"+Blue+"/¯¯\\"+Magenta+"__/\n")
	fmt.Fprintf(w, Blue+"    \\__/\n"+Reset)
	fmt.Fprintf(w, "\n")

	if len(s.PodState) > 0 {
		for name, podState := range s.PodState {
			fmt.Fprintf(w, "%s\t%s\t%s\n", podState.Type, name, podState.Format())
		}
	}

	if len(s.PhaseCount) > 0 {
		header := "Containers:"
		for name, phaseCount := range s.PhaseCount {
			fmt.Fprintf(w, "%s\t%s\t%s\n", header, name, formatPhaseCount(phaseCount))
			header = ""
		}
	}

	if len(s.ImageCount) > 0 {
		header := "Image versions"
		for name, imageCount := range s.ImageCount {
			for image, count := range imageCount {
				fmt.Fprintf(w, "%s\t%s\t%s: %d\n", header, name, image, count)
				header = ""
			}
		}
	}

	header := "Errors:"
	for deployment, pods := range s.Errors {
		for pod, a := range pods {
			for _, err := range a.Errors {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", header, deployment, pod, err)
				header = ""
			}
		}
	}

	header = "Warnings:"
	for deployment, pods := range s.Errors {
		for pod, a := range pods {
			for _, err := range a.Warnings {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", header, deployment, pod, err)
				header = ""
			}
		}
	}

	w.Flush()

	return buf.String()
}
