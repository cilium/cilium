// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/bgp/manager/instance"
	"github.com/cilium/cilium/pkg/bgp/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

// defaultBMPPort is the IANA-assigned TCP port for BGP Monitoring Protocol (RFC 7854).
const defaultBMPPort = 11019

// bmpSysDescr is the sysDescr TLV advertised in the BMP Initiation message.
const bmpSysDescr = "Cilium BGP Control Plane"

// BMPReconciler is a ConfigReconciler which reconciles the BMP (RFC 7854)
// monitoring stations of the provided BGP instance with the desired node config.
type BMPReconciler struct {
	logger   *slog.Logger
	metadata map[string]BMPReconcilerMetadata
}

type BMPReconcilerOut struct {
	cell.Out

	Reconciler ConfigReconciler `group:"bgp-config-reconciler"`
}

type BMPReconcilerIn struct {
	cell.In

	Logger *slog.Logger
}

func NewBMPReconciler(params BMPReconcilerIn) BMPReconcilerOut {
	logger := params.Logger.With(types.ReconcilerLogField, "BMP")

	return BMPReconcilerOut{
		Reconciler: &BMPReconciler{
			logger:   logger,
			metadata: make(map[string]BMPReconcilerMetadata),
		},
	}
}

// BMPReconcilerMetadata keeps a map of running BMP stations to their resolved
// configuration. Key is the BMP server name.
type BMPReconcilerMetadata map[string]*types.BMPServer

func (r *BMPReconciler) getMetadata(i *instance.BGPInstance) BMPReconcilerMetadata {
	return r.metadata[i.Name]
}

func (r *BMPReconciler) Name() string {
	return BMPReconcilerName
}

func (r *BMPReconciler) Priority() int {
	return BMPReconcilerPriority
}

func (r *BMPReconciler) Init(i *instance.BGPInstance) error {
	if i == nil {
		return fmt.Errorf("BUG: %s reconciler initialization with nil BGPInstance", r.Name())
	}
	r.metadata[i.Name] = make(BMPReconcilerMetadata)
	return nil
}

func (r *BMPReconciler) Cleanup(i *instance.BGPInstance) {
	if i != nil {
		delete(r.metadata, i.Name)
	}
}

func (r *BMPReconciler) Reconcile(ctx context.Context, p ReconcileParams) error {
	if err := p.ValidateParams(); err != nil {
		return err
	}

	l := r.logger.With(types.InstanceLogField, p.DesiredConfig.Name)

	current := r.getMetadata(p.BGPInstance)

	// Build the desired set of BMP stations keyed by name.
	desired := make(map[string]*types.BMPServer, len(p.DesiredConfig.BMPServers))
	for i := range p.DesiredConfig.BMPServers {
		srv := toBMPServer(&p.DesiredConfig.BMPServers[i], p.CiliumNode.Name)
		desired[p.DesiredConfig.BMPServers[i].Name] = srv
	}

	var (
		toAdd    []bmpStation
		toRemove []bmpStation
	)

	for name, srv := range desired {
		cur, exists := current[name]
		if !exists {
			toAdd = append(toAdd, bmpStation{name: name, server: srv})
			continue
		}
		// A station whose connection parameters changed must be torn down and
		// re-established, as GoBGP keys BMP sessions by address and port.
		if *cur != *srv {
			toRemove = append(toRemove, bmpStation{name: name, server: cur})
			toAdd = append(toAdd, bmpStation{name: name, server: srv})
		}
	}

	for name, cur := range current {
		if _, exists := desired[name]; !exists {
			toRemove = append(toRemove, bmpStation{name: name, server: cur})
		}
	}

	if len(toAdd) > 0 || len(toRemove) > 0 {
		l.Info("Reconciling BMP stations for instance")
	} else {
		l.Debug("No BMP station changes necessary")
	}

	// Remove stale stations first so that an updated station can be re-added on
	// the same address/port.
	for _, st := range toRemove {
		l.Info("Removing BMP station", types.PeerLogField, st.name)
		if err := p.BGPInstance.Router.RemoveBMP(ctx, st.server); err != nil {
			return fmt.Errorf("failed to remove BMP station %s from instance %s: %w", st.name, p.DesiredConfig.Name, err)
		}
		delete(current, st.name)
	}

	for _, st := range toAdd {
		l.Info("Adding BMP station", types.PeerLogField, st.name)
		if err := p.BGPInstance.Router.AddBMP(ctx, st.server); err != nil {
			return fmt.Errorf("failed to add BMP station %s in instance %s: %w", st.name, p.DesiredConfig.Name, err)
		}
		current[st.name] = st.server
	}

	l.Debug("Done reconciling BMP stations")
	return nil
}

type bmpStation struct {
	name   string
	server *types.BMPServer
}

// toBMPServer converts a CRD CiliumBGPBMPServer into the implementation-agnostic
// types.BMPServer consumed by the Router. sysName is set to the node name so the
// BMP station can attribute the stream to the originating node.
func toBMPServer(s *v2.CiliumBGPBMPServer, nodeName string) *types.BMPServer {
	return &types.BMPServer{
		Address:           s.PeerAddress,
		Port:              uint32(ptr.Deref(s.PeerPort, defaultBMPPort)),
		MonitoringPolicy:  toBMPMonitoringPolicy(ptr.Deref(s.MonitoringPolicy, "pre")),
		StatisticsTimeout: ptr.Deref(s.StatisticsTimeout, 0),
		SysName:           nodeName,
		SysDescr:          bmpSysDescr,
	}
}

// toBMPMonitoringPolicy maps the CRD monitoring policy string to the
// implementation-agnostic types.BMPMonitoringPolicy.
func toBMPMonitoringPolicy(policy string) types.BMPMonitoringPolicy {
	switch policy {
	case "post":
		return types.BMPMonitoringPolicyPost
	case "both":
		return types.BMPMonitoringPolicyBoth
	case "local":
		return types.BMPMonitoringPolicyLocal
	case "all":
		return types.BMPMonitoringPolicyAll
	default:
		return types.BMPMonitoringPolicyPre
	}
}
