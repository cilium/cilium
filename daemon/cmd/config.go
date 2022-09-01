// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"reflect"

	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/daemon"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/eventqueue"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
)

// ConfigModifyEvent is a wrapper around the parameters for configModify.
type ConfigModifyEvent struct {
	params PatchConfigParams
	h      *patchConfig
}

// Handle implements pkg/eventqueue/EventHandler interface.
func (c *ConfigModifyEvent) Handle(res chan interface{}) {
	c.h.configModify(c.params, res)
}

func (h *patchConfig) configModify(params PatchConfigParams, resChan chan interface{}) {
	d := h.daemon

	cfgSpec := params.Configuration

	om, err := option.Config.Opts.Library.ValidateConfigurationMap(cfgSpec.Options)
	if err != nil {
		msg := fmt.Errorf("Invalid configuration option %s", err)
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
		if err := d.Datapath().Loader().Reinitialize(d.ctx, d, d.mtuConfig.GetDeviceMTU(), d.Datapath(), d.l7Proxy); err != nil {
			msg := fmt.Errorf("Unable to recompile base programs: %s", err)
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
	return
}

type patchConfig struct {
	daemon *Daemon
}

func NewPatchConfigHandler(d *Daemon) PatchConfigHandler {
	return &patchConfig{daemon: d}
}

func (h *patchConfig) Handle(params PatchConfigParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("PATCH /config request")

	c := &ConfigModifyEvent{
		params: params,
		h:      h,
	}
	cfgModEvent := eventqueue.NewEvent(c)
	resChan, err := h.daemon.configModifyQueue.Enqueue(cfgModEvent)
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

type getConfig struct {
	daemon *Daemon
}

func NewGetConfigHandler(d *Daemon) GetConfigHandler {
	return &getConfig{daemon: d}
}

func (h *getConfig) Handle(params GetConfigParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /config request")

	d := h.daemon
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
		GROMaxSize:                  int64(d.bigTCPConfig.GetGROMaxSize()),
		GSOMaxSize:                  int64(d.bigTCPConfig.GetGSOMaxSize()),
	}

	cfg := &models.DaemonConfiguration{
		Spec:   spec,
		Status: status,
	}

	return NewGetConfigOK().WithPayload(cfg)
}
