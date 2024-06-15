// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package restapi

import (
	"context"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/go-openapi/runtime/middleware"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/api/v1/models"
	daemonapi "github.com/cilium/cilium/api/v1/server/restapi/daemon"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/datapath/linux/bigtcp"
	datapathTables "github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/eventqueue"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	monitorAgent "github.com/cilium/cilium/pkg/monitor/agent"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy"
	"github.com/cilium/cilium/pkg/trigger"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

const (
	// ConfigModifyQueueSize is the size of the event queue for serializing
	// configuration updates to the daemon
	ConfigModifyQueueSize = 10
)

var configModificationCell = cell.Module(
	"config-modification",
	"Config modification via REST API",

	cell.Provide(newConfigModifyApiHandler),
	cell.Provide(newConfigModifyEventHandler),
)

type configModifyApiHandlerParams struct {
	cell.In

	Logger logrus.FieldLogger

	DB           *statedb.DB
	Devices      statedb.Table[*datapathTables.Device]
	Clientset    k8sClient.Clientset
	MonitorAgent monitorAgent.Agent
	MTUConfig    mtu.MTU
	BigTCPConfig *bigtcp.Configuration
	TunnelConfig tunnel.Config

	EventHandler *ConfigModifyEventHandler
}

type configModifyApiHandlerOut struct {
	cell.Out

	GetConfigHandler   daemonapi.GetConfigHandler
	PatchConfigHandler daemonapi.PatchConfigHandler
}

func newConfigModifyApiHandler(params configModifyApiHandlerParams) configModifyApiHandlerOut {
	return configModifyApiHandlerOut{
		GetConfigHandler: &getConfigHandler{
			logger:       params.Logger,
			db:           params.DB,
			devices:      params.Devices,
			clientset:    params.Clientset,
			monitorAgent: params.MonitorAgent,
			mtuConfig:    params.MTUConfig,
			bigTCPConfig: params.BigTCPConfig,
			tunnelConfig: params.TunnelConfig,
		},
		PatchConfigHandler: &patchConfigHandler{
			logger:       params.Logger,
			eventHandler: params.EventHandler,
		},
	}
}

type configModifyEventHandlerParams struct {
	cell.In

	Lifecycle cell.Lifecycle
	Logger    logrus.FieldLogger

	Datapath        datapath.Datapath
	Policy          *policy.Repository
	EndpointManager endpointmanager.EndpointManager
	L7Proxy         *proxy.Proxy
}

func newConfigModifyEventHandler(params configModifyEventHandlerParams) *ConfigModifyEventHandler {
	ctx, cancel := context.WithCancel(context.Background())

	eventHandler := &ConfigModifyEventHandler{
		ctx:             ctx,
		logger:          params.Logger,
		datapath:        params.Datapath,
		policy:          params.Policy,
		endpointManager: params.EndpointManager,
		l7Proxy:         params.L7Proxy,
	}

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(hookContext cell.HookContext) error {
			// Reuse policy.TriggerMetrics and PolicyTriggerInterval here since
			// this is only triggered by agent configuration changes for now and
			// should be counted in pol.TriggerMetrics.
			rt, err := trigger.NewTrigger(trigger.Parameters{
				Name:            "datapath-regeneration",
				MetricsObserver: &policy.TriggerMetrics{},
				MinInterval:     option.Config.PolicyTriggerInterval,
				TriggerFunc:     eventHandler.datapathRegen,
			})
			if err != nil {
				return fmt.Errorf("failed to create datapath regeneration trigger: %w", err)
			}
			eventHandler.datapathRegenTrigger = rt

			eventHandler.configModifyQueue = eventqueue.NewEventQueueBuffered("config-modify-queue", ConfigModifyQueueSize)
			eventHandler.configModifyQueue.Run()

			return nil
		},
		OnStop: func(hookContext cell.HookContext) error {
			if eventHandler.datapathRegenTrigger != nil {
				eventHandler.datapathRegenTrigger.Shutdown()
			}
			cancel()
			return nil
		},
	})

	return eventHandler
}

type ConfigModifyEventHandler struct {
	ctx    context.Context
	logger logrus.FieldLogger

	datapathRegenTrigger *trigger.Trigger
	// event queue for serializing configuration updates to the daemon.
	configModifyQueue *eventqueue.EventQueue

	datapath        datapath.Datapath
	policy          *policy.Repository
	endpointManager endpointmanager.EndpointManager
	l7Proxy         *proxy.Proxy
}

func (h *ConfigModifyEventHandler) datapathRegen(reasons []string) {
	reason := strings.Join(reasons, ", ")

	regenerationMetadata := &regeneration.ExternalRegenerationMetadata{
		Reason:            reason,
		RegenerationLevel: regeneration.RegenerateWithDatapath,
	}
	h.endpointManager.RegenerateAllEndpoints(regenerationMetadata)
}

func (h *ConfigModifyEventHandler) configModify(params daemonapi.PatchConfigParams, resChan chan interface{}) {
	cfgSpec := params.Configuration

	om, err := option.Config.Opts.Library.ValidateConfigurationMap(cfgSpec.Options)
	if err != nil {
		msg := fmt.Errorf("invalid configuration option: %w", err)
		resChan <- api.Error(daemonapi.PatchConfigBadRequestCode, msg)
		return
	}

	// Serialize configuration updates to the daemon.
	option.Config.ConfigPatchMutex.Lock()

	// Track changes to daemon's configuration
	var changes int
	var policyEnforcementChanged bool
	// Copy old configurations for potential reversion
	oldEnforcementValue := policy.GetPolicyEnabled()
	oldConfigOpts := make(option.OptionMap, len(om))
	for k := range om {
		oldConfigOpts[k] = option.Config.Opts.Opts[k]
	}

	// Only update if value provided for PolicyEnforcement.
	if enforcement := cfgSpec.PolicyEnforcement; enforcement != "" {
		switch enforcement {
		case option.NeverEnforce, option.DefaultEnforcement, option.AlwaysEnforce:
			// If the policy enforcement configuration has indeed changed, we have
			// to regenerate endpoints and update daemon's configuration.
			if enforcement != oldEnforcementValue {
				h.logger.Debug("configuration request to change PolicyEnforcement for daemon")
				changes++
				policy.SetPolicyEnabled(enforcement)
				policyEnforcementChanged = true
			}

		default:
			msg := fmt.Errorf("invalid option for PolicyEnforcement %s", enforcement)
			h.logger.Warn(msg)
			option.Config.ConfigPatchMutex.Unlock()
			resChan <- api.Error(daemonapi.PatchConfigBadRequestCode, msg)
			return
		}
		h.logger.Debug("finished configuring PolicyEnforcement for daemon")
	}

	changes += option.Config.Opts.ApplyValidated(om, h.changedOption, nil)
	h.endpointManager.OverrideEndpointOpts(om)

	h.logger.WithField("count", changes).Debug("Applied changes to daemon's configuration")
	option.Config.ConfigPatchMutex.Unlock()

	if changes > 0 {
		// Only recompile if configuration has changed.
		h.logger.Debug("daemon configuration has changed; recompiling base programs")
		if err := h.datapath.Orchestrator().Reinitialize(h.ctx); err != nil {
			msg := fmt.Errorf("unable to recompile base programs: %w", err)
			// Revert configuration changes
			option.Config.ConfigPatchMutex.Lock()
			if policyEnforcementChanged {
				policy.SetPolicyEnabled(oldEnforcementValue)
			}
			option.Config.Opts.ApplyValidated(oldConfigOpts, func(string, option.OptionSetting, interface{}) {}, h)
			h.endpointManager.OverrideEndpointOpts(oldConfigOpts)
			option.Config.ConfigPatchMutex.Unlock()
			h.logger.Debug("finished reverting agent configuration changes")
			resChan <- api.Error(daemonapi.PatchConfigFailureCode, msg)
			return
		}
		// Most agent configuration changes require endpoint datapath regeneration,
		// trigger datapath regeneration anyway in case we miss the regeneration
		// due to a future change in BPF code.
		h.triggerDatapathRegen(policyEnforcementChanged, "agent configuration update")
	}

	resChan <- daemonapi.NewPatchConfigOK()
}

func (h *ConfigModifyEventHandler) changedOption(key string, value option.OptionSetting, _ interface{}) {
	if key == option.Debug {
		// Set the debug toggle (this can be a no-op)
		if option.Config.Opts.IsEnabled(option.Debug) {
			logging.SetLogLevelToDebug()
		}
		// Reflect log level change to proxies
		// Might not be initialized yet
		if option.Config.EnableL7Proxy {
			h.l7Proxy.ChangeLogLevel(logging.GetLevel(logging.DefaultLogger))
		}
	}
	h.policy.BumpRevision() // force policy recalculation
}

// triggerDatapathRegen triggers datapath rewrite for every daemon's endpoint.
// This is only called after agent configuration changes for now. Policy revision
// needs to be increased on PolicyEnforcement mode change.
func (h *ConfigModifyEventHandler) triggerDatapathRegen(force bool, reason string) {
	if force {
		h.logger.Debug("PolicyEnforcement mode changed, increasing policy revision to enforce policy recalculation")
		h.policy.BumpRevision()
	}
	h.datapathRegenTrigger.TriggerWithReason(reason)
}

// ConfigModifyEvent is a wrapper around the parameters for configModify.
type ConfigModifyEvent struct {
	params       daemonapi.PatchConfigParams
	eventHandler *ConfigModifyEventHandler
}

// Handle implements pkg/eventqueue/EventHandler interface.
func (e *ConfigModifyEvent) Handle(res chan interface{}) {
	e.eventHandler.configModify(e.params, res)
}

type patchConfigHandler struct {
	logger       logrus.FieldLogger
	eventHandler *ConfigModifyEventHandler
}

func (h *patchConfigHandler) Handle(params daemonapi.PatchConfigParams) middleware.Responder {
	h.logger.WithField(logfields.Params, logfields.Repr(params)).Debug("PATCH /config request")

	c := &ConfigModifyEvent{
		params:       params,
		eventHandler: h.eventHandler,
	}
	cfgModEvent := eventqueue.NewEvent(c)
	resChan, err := h.eventHandler.configModifyQueue.Enqueue(cfgModEvent)
	if err != nil {
		msg := fmt.Errorf("enqueue of ConfigModifyEvent failed: %w", err)
		return api.Error(daemonapi.PatchConfigFailureCode, msg)
	}

	res, ok := <-resChan
	if ok {
		return res.(middleware.Responder)
	}

	msg := fmt.Errorf("config modify event was cancelled")
	return api.Error(daemonapi.PatchConfigFailureCode, msg)
}

type getConfigHandler struct {
	logger logrus.FieldLogger

	db           *statedb.DB
	devices      statedb.Table[*datapathTables.Device]
	clientset    k8sClient.Clientset
	monitorAgent monitorAgent.Agent
	mtuConfig    mtu.MTU
	bigTCPConfig *bigtcp.Configuration
	tunnelConfig tunnel.Config
}

func (h *getConfigHandler) Handle(params daemonapi.GetConfigParams) middleware.Responder {
	h.logger.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /config request")

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
	devs, _ := datapathTables.SelectedDevices(h.devices, h.db.ReadTxn())
	m["Devices"] = datapathTables.DeviceNames(devs)

	spec := &models.DaemonConfigurationSpec{
		Options:           *option.Config.Opts.GetMutableModel(),
		PolicyEnforcement: policy.GetPolicyEnabled(),
	}

	status := &models.DaemonConfigurationStatus{
		Addressing:       node.GetNodeAddressing(),
		K8sConfiguration: h.clientset.Config().K8sKubeConfigPath,
		K8sEndpoint:      h.clientset.Config().K8sAPIServer,
		NodeMonitor:      h.monitorAgent.State(),
		KvstoreConfiguration: &models.KVstoreConfiguration{
			Type:    option.Config.KVStore,
			Options: option.Config.KVStoreOpt,
		},
		Realized:                     spec,
		DaemonConfigurationMap:       m,
		DeviceMTU:                    int64(h.mtuConfig.GetDeviceMTU()),
		RouteMTU:                     int64(h.mtuConfig.GetRouteMTU()),
		EnableRouteMTUForCNIChaining: h.mtuConfig.IsEnableRouteMTUForCNIChaining(),
		DatapathMode:                 models.DatapathMode(option.Config.DatapathMode),
		IpamMode:                     option.Config.IPAM,
		Masquerade:                   option.Config.MasqueradingEnabled(),
		MasqueradeProtocols: &models.DaemonConfigurationStatusMasqueradeProtocols{
			IPV4: option.Config.EnableIPv4Masquerade,
			IPV6: option.Config.EnableIPv6Masquerade,
		},
		EgressMultiHomeIPRuleCompat: option.Config.EgressMultiHomeIPRuleCompat,
		GROMaxSize:                  int64(h.bigTCPConfig.GetGROIPv6MaxSize()),
		GSOMaxSize:                  int64(h.bigTCPConfig.GetGSOIPv6MaxSize()),
		GROIPV4MaxSize:              int64(h.bigTCPConfig.GetGROIPv4MaxSize()),
		GSOIPV4MaxSize:              int64(h.bigTCPConfig.GetGSOIPv4MaxSize()),
		IPLocalReservedPorts:        h.getIPLocalReservedPorts(),
	}

	cfg := &models.DaemonConfiguration{
		Spec:   spec,
		Status: status,
	}

	return daemonapi.NewGetConfigOK().WithPayload(cfg)
}

// getIPLocalReservedPorts returns a comma-separated list of ports which
// we need to reserve in the container network namespace.
// These ports are typically used in the host network namespace and thus can
// conflict when running with DNS transparent proxy mode.
// This is a workaround for cilium/cilium#31535
func (h *getConfigHandler) getIPLocalReservedPorts() string {
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
	if h.tunnelConfig.Protocol() != tunnel.Disabled {
		ports = append(ports, fmt.Sprintf("%d", h.tunnelConfig.Port()))
	}

	h.logger.WithField(logfields.Ports, ports).
		Info("Auto-detected local ports to reserve in the container namespace for transparent DNS proxy")

	return strings.Join(ports, ",")
}
