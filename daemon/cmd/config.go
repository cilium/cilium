// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/daemon"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/eventqueue"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

// ConfigModifyEvent is a wrapper around the parameters for configModify.
type ConfigModifyEvent struct {
	params PatchConfigParams
	daemon *Daemon
}

// Handle implements pkg/eventqueue/EventHandler interface.
func (c *ConfigModifyEvent) Handle(res chan interface{}) {
	c.configModify(c.params, res)
}

func (c *ConfigModifyEvent) configModify(params PatchConfigParams, resChan chan interface{}) {
	d := c.daemon

	cfgSpec := params.Configuration

	om, err := option.Config.Opts.Library.ValidateConfigurationMap(cfgSpec.Options)
	if err != nil {
		msg := fmt.Errorf("Invalid configuration option: %w", err)
		resChan <- api.Error(PatchConfigBadRequestCode, msg)
		return
	}

	// Serialize configuration updates to the daemon.
	option.Config.ConfigPatchMutex.Lock()

	// Track changes to daemon's configuration
	var changes int
	var policyEnforcementChanged bool
	// Copy old configurations for potential reversion
	oldEnforcementValue := policy.GetPolicyEnabled()
	oldConfigOpts := option.Config.Opts.DeepCopy()
	oldEpConfigOpts := make(option.OptionMap, len(om))
	for k := range om {
		oldEpConfigOpts[k] = oldConfigOpts.Opts[k]
	}

	// Only update if value provided for PolicyEnforcement.
	if enforcement := cfgSpec.PolicyEnforcement; enforcement != "" {
		switch enforcement {
		case option.NeverEnforce, option.DefaultEnforcement, option.AlwaysEnforce:
			// If the policy enforcement configuration has indeed changed, we have
			// to regenerate endpoints and update daemon's configuration.
			if enforcement != oldEnforcementValue {
				log.Debug("configuration request to change PolicyEnforcement for daemon")
				changes++
				policy.SetPolicyEnabled(enforcement)
				policyEnforcementChanged = true
			}

		default:
			msg := fmt.Errorf("Invalid option for PolicyEnforcement %s", enforcement)
			log.Warn(msg)
			option.Config.ConfigPatchMutex.Unlock()
			resChan <- api.Error(PatchConfigBadRequestCode, msg)
			return
		}
		log.Debug("finished configuring PolicyEnforcement for daemon")
	}

	changes += option.Config.Opts.ApplyValidated(om, changedOption, d)
	d.endpointManager.OverrideEndpointOpts(om)

	log.WithField("count", changes).Debug("Applied changes to daemon's configuration")
	option.Config.ConfigPatchMutex.Unlock()

	if changes > 0 {
		// Only recompile if configuration has changed.
		log.Debug("daemon configuration has changed; recompiling base programs")
		if err := d.Datapath().Loader().Reinitialize(d.ctx, d, d.tunnelConfig, d.mtuConfig.GetDeviceMTU(), d.Datapath(), d.l7Proxy); err != nil {
			msg := fmt.Errorf("Unable to recompile base programs: %w", err)
			// Revert configuration changes
			option.Config.ConfigPatchMutex.Lock()
			if policyEnforcementChanged {
				policy.SetPolicyEnabled(oldEnforcementValue)
			}
			option.Config.Opts = oldConfigOpts
			d.endpointManager.OverrideEndpointOpts(oldEpConfigOpts)
			option.Config.ConfigPatchMutex.Unlock()
			log.Debug("finished reverting agent configuration changes")
			resChan <- api.Error(PatchConfigFailureCode, msg)
			return
		}
		// Most agent configuration changes require endpoint datapath regeneration,
		// trigger datapath regeneration anyway in case we miss the regeneration
		// due to a future change in BPF code.
		d.TriggerDatapathRegen(policyEnforcementChanged, "agent configuration update")
	}

	resChan <- NewPatchConfigOK()
}

func patchConfigHandler(d *Daemon, params PatchConfigParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("PATCH /config request")

	c := &ConfigModifyEvent{
		params: params,
		daemon: d,
	}
	cfgModEvent := eventqueue.NewEvent(c)
	resChan, err := d.configModifyQueue.Enqueue(cfgModEvent)
	if err != nil {
		msg := fmt.Errorf("enqueue of ConfigModifyEvent failed: %w", err)
		return api.Error(PatchConfigFailureCode, msg)
	}

	res, ok := <-resChan
	if ok {
		return res.(middleware.Responder)
	}

	msg := fmt.Errorf("config modify event was cancelled")
	return api.Error(PatchConfigFailureCode, msg)
}

// getIPLocalReservedPorts returns a comma-separated list of ports which
// we need to reserve in the container network namespace.
// These ports are typically used in the host network namespace and thus can
// conflict when running with DNS transparent proxy mode.
// This is a workaround for cilium/cilium#31535
func getIPLocalReservedPorts(d *Daemon) string {
	if option.Config.ContainerIPLocalReservedPorts != defaults.ContainerIPLocalReservedPortsAuto {
		return option.Config.ContainerIPLocalReservedPorts
	}

	if !option.Config.DNSProxyEnableTransparentMode {
		return "" // no ports to reserve
	}

	// Reserves the WireGuard port. This is usually part of the ephemeral port
	// range and thus may conflict with the ephemeral source port of DNS clients
	// in the container network namespace.
	var ports []string
	if option.Config.EnableWireguard {
		ports = append(ports, strconv.Itoa(wgTypes.ListenPort))
	}

	// Reserves the tunnel port. This is not part of the ephemeral port range by
	// default, but is user configurable and thus should be included regardless.
	// The Linux kernel documentation explicitly allows to reserve ports which
	// are not part of the ephemeral port range, in which case this is a no-op.
	if d.tunnelConfig.Protocol() != tunnel.Disabled {
		ports = append(ports, fmt.Sprintf("%d", d.tunnelConfig.Port()))
	}

	log.WithField(logfields.Ports, ports).
		Info("Auto-detected local ports to reserve in the container namespace for transparent DNS proxy")

	return strings.Join(ports, ",")
}

func getConfigHandler(d *Daemon, params GetConfigParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /config request")

	m := make(map[string]interface{})
	option.Config.ConfigPatchMutex.RLock()
	e := reflect.ValueOf(option.Config).Elem()

	for i := 0; i < e.NumField(); i++ {
		if e.Field(i).Kind() != reflect.Func {
			field := e.Type().Field(i)
			// Only consider exported fields and ignore the mutable options.
			if field.IsExported() && field.Name != "Opts" && field.Name != "ConfigPatchMutex" {
				m[e.Type().Field(i).Name] = e.Field(i).Interface()
			}
		}
	}
	option.Config.ConfigPatchMutex.RUnlock()

	// Manually add fields that are behind accessors.
	m["Devices"] = option.Config.GetDevices()

	spec := &models.DaemonConfigurationSpec{
		Options:           *option.Config.Opts.GetMutableModel(),
		PolicyEnforcement: policy.GetPolicyEnabled(),
	}

	status := &models.DaemonConfigurationStatus{
		Addressing:       node.GetNodeAddressing(),
		K8sConfiguration: d.clientset.Config().K8sKubeConfigPath,
		K8sEndpoint:      d.clientset.Config().K8sAPIServer,
		NodeMonitor:      d.monitorAgent.State(),
		KvstoreConfiguration: &models.KVstoreConfiguration{
			Type:    option.Config.KVStore,
			Options: option.Config.KVStoreOpt,
		},
		Realized:               spec,
		DaemonConfigurationMap: m,
		DeviceMTU:              int64(d.mtuConfig.GetDeviceMTU()),
		RouteMTU:               int64(d.mtuConfig.GetRouteMTU()),
		DatapathMode:           models.DatapathMode(option.Config.DatapathMode),
		IpamMode:               option.Config.IPAM,
		Masquerade:             option.Config.MasqueradingEnabled(),
		MasqueradeProtocols: &models.DaemonConfigurationStatusMasqueradeProtocols{
			IPV4: option.Config.EnableIPv4Masquerade,
			IPV6: option.Config.EnableIPv6Masquerade,
		},
		EgressMultiHomeIPRuleCompat: option.Config.EgressMultiHomeIPRuleCompat,
		GROMaxSize:                  int64(d.bigTCPConfig.GetGROIPv6MaxSize()),
		GSOMaxSize:                  int64(d.bigTCPConfig.GetGSOIPv6MaxSize()),
		GROIPV4MaxSize:              int64(d.bigTCPConfig.GetGROIPv4MaxSize()),
		GSOIPV4MaxSize:              int64(d.bigTCPConfig.GetGSOIPv4MaxSize()),
		IPLocalReservedPorts:        getIPLocalReservedPorts(d),
	}

	cfg := &models.DaemonConfiguration{
		Spec:   spec,
		Status: status,
	}

	return NewGetConfigOK().WithPayload(cfg)
}
