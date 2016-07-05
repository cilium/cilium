package report

import (
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/weaveworks/scope/common/mtime"
	"github.com/weaveworks/scope/common/xfer"
)

// Names of the various topologies.
const (
	Endpoint       = "endpoint"
	Process        = "process"
	Container      = "container"
	Pod            = "pod"
	Service        = "service"
	Deployment     = "deployment"
	ReplicaSet     = "replica_set"
	ContainerImage = "container_image"
	Host           = "host"
	Overlay        = "overlay"

	// Shapes used for different nodes
	Circle   = "circle"
	Square   = "square"
	Heptagon = "heptagon"
	Hexagon  = "hexagon"
	Cloud    = "cloud"

	// Used when counting the number of containers
	ContainersKey = "containers"
)

// Report is the core data type. It's produced by probes, and consumed and
// stored by apps. It's composed of multiple topologies, each representing
// a different (related, but not equivalent) view of the network.
type Report struct {
	// Endpoint nodes are individual (address, port) tuples on each host.
	// They come from inspecting active connections and can (theoretically)
	// be traced back to a process. Edges are present.
	Endpoint Topology

	// Process nodes are processes on each host. Edges are not present.
	Process Topology

	// Container nodes represent all Docker containers on hosts running probes.
	// Metadata includes things like containter id, name, image id etc.
	// Edges are not present.
	Container Topology

	// Pod nodes represent all Kubernetes pods running on hosts running probes.
	// Metadata includes things like pod id, name etc. Edges are not
	// present.
	Pod Topology

	// Service nodes represent all Kubernetes services running on hosts running probes.
	// Metadata includes things like service id, name etc. Edges are not
	// present.
	Service Topology

	// Deployment nodes represent all Kubernetes deployments running on hosts running probes.
	// Metadata includes things like deployment id, name etc. Edges are not
	// present.
	Deployment Topology

	// ReplicaSet nodes represent all Kubernetes ReplicaSets running on hosts running probes.
	// Metadata includes things like ReplicaSet id, name etc. Edges are not
	// present.
	ReplicaSet Topology

	// ContainerImages nodes represent all Docker containers images on
	// hosts running probes. Metadata includes things like image id, name etc.
	// Edges are not present.
	ContainerImage Topology

	// Host nodes are physical hosts that run probes. Metadata includes things
	// like operating system, load, etc. The information is scraped by the
	// probes with each published report. Edges are not present.
	Host Topology

	// Overlay nodes are active peers in any software-defined network that's
	// overlaid on the infrastructure. The information is scraped by polling
	// their status endpoints. Edges could be present, but aren't currently.
	Overlay Topology

	// Sampling data for this report.
	Sampling Sampling

	// Window is the amount of time that this report purports to represent.
	// Windows must be carefully merged. They should only be added when
	// reports cover non-overlapping periods of time. By default, we assume
	// that's true, and add windows in merge operations. When that's not true,
	// such as in the app, we expect the component to overwrite the window
	// before serving it to consumers.
	Window time.Duration

	// Shortcut reports should be propagated to the UI as quickly as possible,
	// bypassing the usual spy interval, publish interval and app ws interval.
	Shortcut bool

	Plugins xfer.PluginSpecs

	// ID a random identifier for this report, used when caching
	// rendered views of the report.  Reports with the same id
	// must be equal, but we don't require that equal reports have
	// the same id.
	ID string `deepequal:"skip"`
}

// MakeReport makes a clean report, ready to Merge() other reports into.
func MakeReport() Report {
	return Report{
		Endpoint: MakeTopology(),

		Process: MakeTopology().
			WithShape(Square).
			WithLabel("process", "processes"),

		Container: MakeTopology().
			WithShape(Hexagon).
			WithLabel("container", "containers"),

		ContainerImage: MakeTopology().
			WithShape(Hexagon).
			WithLabel("image", "images"),

		Host: MakeTopology().
			WithShape(Circle).
			WithLabel("host", "hosts"),

		Pod: MakeTopology().
			WithShape(Heptagon).
			WithLabel("pod", "pods"),

		Service: MakeTopology().
			WithShape(Heptagon).
			WithLabel("service", "services"),

		Deployment: MakeTopology().
			WithShape(Heptagon).
			WithLabel("deployment", "deployments"),

		ReplicaSet: MakeTopology().
			WithShape(Heptagon).
			WithLabel("replica set", "replica sets"),

		Overlay: MakeTopology(),

		Sampling: Sampling{},
		Window:   0,
		Plugins:  xfer.MakePluginSpecs(),
		ID:       fmt.Sprintf("%d", rand.Int63()),
	}
}

// Copy returns a value copy of the report.
func (r Report) Copy() Report {
	return Report{
		Endpoint:       r.Endpoint.Copy(),
		Process:        r.Process.Copy(),
		Container:      r.Container.Copy(),
		ContainerImage: r.ContainerImage.Copy(),
		Host:           r.Host.Copy(),
		Pod:            r.Pod.Copy(),
		Service:        r.Service.Copy(),
		Deployment:     r.Deployment.Copy(),
		ReplicaSet:     r.ReplicaSet.Copy(),
		Overlay:        r.Overlay.Copy(),
		Sampling:       r.Sampling,
		Window:         r.Window,
		Plugins:        r.Plugins.Copy(),
		ID:             fmt.Sprintf("%d", rand.Int63()),
	}
}

// Merge merges another Report into the receiver and returns the result. The
// original is not modified.
func (r Report) Merge(other Report) Report {
	return Report{
		Endpoint:       r.Endpoint.Merge(other.Endpoint),
		Process:        r.Process.Merge(other.Process),
		Container:      r.Container.Merge(other.Container),
		ContainerImage: r.ContainerImage.Merge(other.ContainerImage),
		Host:           r.Host.Merge(other.Host),
		Pod:            r.Pod.Merge(other.Pod),
		Service:        r.Service.Merge(other.Service),
		Deployment:     r.Deployment.Merge(other.Deployment),
		ReplicaSet:     r.ReplicaSet.Merge(other.ReplicaSet),
		Overlay:        r.Overlay.Merge(other.Overlay),
		Sampling:       r.Sampling.Merge(other.Sampling),
		Window:         r.Window + other.Window,
		Plugins:        r.Plugins.Merge(other.Plugins),
		ID:             fmt.Sprintf("%d", rand.Int63()),
	}
}

// Topologies returns a slice of Topologies in this report
func (r Report) Topologies() []Topology {
	result := []Topology{}
	r.WalkTopologies(func(t *Topology) {
		result = append(result, *t)
	})
	return result
}

// WalkTopologies iterates through the Topologies of the report,
// potentially modifying them
func (r *Report) WalkTopologies(f func(*Topology)) {
	f(&r.Endpoint)
	f(&r.Process)
	f(&r.Container)
	f(&r.ContainerImage)
	f(&r.Pod)
	f(&r.Service)
	f(&r.Deployment)
	f(&r.ReplicaSet)
	f(&r.Host)
	f(&r.Overlay)
}

// Topology gets a topology by name
func (r Report) Topology(name string) (Topology, bool) {
	t, ok := map[string]Topology{
		Endpoint:       r.Endpoint,
		Process:        r.Process,
		Container:      r.Container,
		ContainerImage: r.ContainerImage,
		Pod:            r.Pod,
		Service:        r.Service,
		Deployment:     r.Deployment,
		ReplicaSet:     r.ReplicaSet,
		Host:           r.Host,
		Overlay:        r.Overlay,
	}[name]
	return t, ok
}

// Validate checks the report for various inconsistencies.
func (r Report) Validate() error {
	var errs []string
	for _, topology := range r.Topologies() {
		if err := topology.Validate(); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if r.Sampling.Count > r.Sampling.Total {
		errs = append(errs, fmt.Sprintf("sampling count (%d) bigger than total (%d)", r.Sampling.Count, r.Sampling.Total))
	}
	if len(errs) > 0 {
		return fmt.Errorf("%d error(s): %s", len(errs), strings.Join(errs, "; "))
	}
	return nil
}

// Upgrade returns a new report based on a report received from the old probe.
//
// This for now creates node's LatestControls from Controls.
func (r Report) Upgrade() Report {
	cp := r.Copy()
	ncd := NodeControlData{
		Dead: false,
	}
	cp.WalkTopologies(func(topology *Topology) {
		n := Nodes{}
		for name, node := range topology.Nodes {
			if node.LatestControls.Size() == 0 && len(node.Controls.Controls) > 0 {
				for _, control := range node.Controls.Controls {
					node.LatestControls = node.LatestControls.Set(control, node.Controls.Timestamp, ncd)
				}
			}
			n[name] = node
		}
		topology.Nodes = n
	})
	return cp
}

// BackwardCompatible returns a new backward-compatible report.
//
// This for now creates node's Controls from LatestControls.
func (r Report) BackwardCompatible() Report {
	now := mtime.Now()
	cp := r.Copy()
	cp.WalkTopologies(func(topology *Topology) {
		n := Nodes{}
		for name, node := range topology.Nodes {
			var controls []string
			node.LatestControls.ForEach(func(k string, _ time.Time, v NodeControlData) {
				if !v.Dead {
					controls = append(controls, k)
				}
			})
			if len(controls) > 0 {
				node.Controls = NodeControls{
					Timestamp: now,
					Controls:  MakeStringSet(controls...),
				}
			}
			n[name] = node
		}
		topology.Nodes = n
	})
	return cp
}

// Sampling describes how the packet data sources for this report were
// sampled. It can be used to calculate effective sample rates. We can't
// just put the rate here, because that can't be accurately merged. Counts
// in e.g. edge metadata structures have already been adjusted to
// compensate for the sample rate.
type Sampling struct {
	Count uint64 // observed and processed
	Total uint64 // observed overall
}

// Rate returns the effective sampling rate.
func (s Sampling) Rate() float64 {
	if s.Total <= 0 {
		return 1.0
	}
	return float64(s.Count) / float64(s.Total)
}

// Merge combines two sampling structures via simple addition and returns the
// result. The original is not modified.
func (s Sampling) Merge(other Sampling) Sampling {
	return Sampling{
		Count: s.Count + other.Count,
		Total: s.Total + other.Total,
	}
}

const (
	// HostNodeID is a metadata foreign key, linking a node in any topology to
	// a node in the host topology. That host node is the origin host, where
	// the node was originally detected.
	HostNodeID = "host_node_id"
	// ControlProbeID is the random ID of the probe which controls the specific node.
	ControlProbeID = "control_probe_id"
)
