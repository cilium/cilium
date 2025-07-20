// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bigtcp

import (
	"errors"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

const (
	defaultGROMaxSize = 65536
	defaultGSOMaxSize = 65536

	bigTCPGROMaxSize = 196608
	bigTCPGSOMaxSize = 196608

	probeDevice = "lo"
)

var defaultUserConfig = types.BigTCPUserConfig{
	EnableIPv6BIGTCP: false,
	EnableIPv4BIGTCP: false,
}

var Cell = cell.Module(
	"bigtcp",
	"BIG TCP support",

	cell.Config(defaultUserConfig),
	cell.Provide(newBIGTCP,
		func(c types.BigTCPUserConfig) types.BigTCPConfig { return c }),
	cell.Invoke(func(*Configuration) {}),
)

func newDefaultConfiguration(userConfig types.BigTCPUserConfig) *Configuration {
	return &Configuration{
		BigTCPUserConfig: userConfig,
		groIPv4MaxSize:   defaultGROMaxSize,
		gsoIPv4MaxSize:   defaultGSOMaxSize,
		groIPv6MaxSize:   defaultGROMaxSize,
		gsoIPv6MaxSize:   defaultGSOMaxSize,
	}
}

// Configuration is the BIG TCP configuration. The values are finalized after
// BIG TCP has started and must not be read before that.
type Configuration struct {
	types.BigTCPUserConfig

	// gsoIPv{4,6}MaxSize is the GSO maximum size used when configuring
	// devices.
	//
	// Note that this is a singleton for the process including this
	// package. This means, for instance, that when using this from the
	// ``pkg/plugins/*`` sources, it will not respect the settings
	// configured inside the ``daemon/``.
	gsoIPv4MaxSize int
	gsoIPv6MaxSize int

	// groIPv{4,6}MaxSize is the GRO maximum size used when configuring
	// devices.
	//
	// Note that this is a singleton for the process including this
	// package. This means, for instance, that when using this from the
	// ``pkg/plugins/*`` sources, it will not respect the settings
	// configured inside the ``daemon/``.
	groIPv4MaxSize int
	groIPv6MaxSize int
}

func (c *Configuration) GetGROIPv6MaxSize() int {
	return c.groIPv6MaxSize
}

func (c *Configuration) GetGSOIPv6MaxSize() int {
	return c.gsoIPv6MaxSize
}

func (c *Configuration) GetGROIPv4MaxSize() int {
	return c.groIPv4MaxSize
}

func (c *Configuration) GetGSOIPv4MaxSize() int {
	return c.gsoIPv4MaxSize
}

// If an error is returned the caller is responsible for rolling back
// any partial changes.
func setGROGSOIPv6MaxSize(log *slog.Logger, userConfig types.BigTCPUserConfig, device string, GROMaxSize, GSOMaxSize int) error {
	link, err := safenetlink.LinkByName(device)
	if err != nil {
		log.Warn("Link does not exist",
			logfields.Device, device,
			logfields.Error, err,
		)
		return nil
	}

	attrs := link.Attrs()
	// The check below is needed to avoid trying to change GSO/GRO max sizes
	// when that is not necessary (e.g. BIG TCP was never enabled or current
	// size matches the target size we need).
	if (int(attrs.GROMaxSize) == GROMaxSize && int(attrs.GSOMaxSize) == GSOMaxSize) ||
		(!userConfig.EnableIPv6BIGTCP &&
			int(attrs.GROMaxSize) <= GROMaxSize &&
			int(attrs.GSOMaxSize) <= GSOMaxSize) {
		return nil
	}

	err = netlink.LinkSetGROMaxSize(link, GROMaxSize)
	if err != nil {
		return err
	}

	return netlink.LinkSetGSOMaxSize(link, GSOMaxSize)
}

// If an error is returned the caller is responsible for rolling back
// any partial changes.
func setGROGSOIPv4MaxSize(log *slog.Logger, userConfig types.BigTCPUserConfig, device string, GROMaxSize, GSOMaxSize int) error {
	link, err := safenetlink.LinkByName(device)
	if err != nil {
		log.Warn("Link does not exist",
			logfields.Device, device,
			logfields.Error, err,
		)
		return nil
	}

	attrs := link.Attrs()
	// The check below is needed to avoid trying to change GSO/GRO max sizes
	// when that is not necessary (e.g. BIG TCP was never enabled or current
	// size matches the target size we need).
	if (int(attrs.GROIPv4MaxSize) == GROMaxSize && int(attrs.GSOIPv4MaxSize) == GSOMaxSize) ||
		(!userConfig.EnableIPv4BIGTCP &&
			int(attrs.GROIPv4MaxSize) <= GROMaxSize &&
			int(attrs.GSOIPv4MaxSize) <= GSOMaxSize) {
		return nil
	}

	err = netlink.LinkSetGROIPv4MaxSize(link, GROMaxSize)
	if err != nil {
		return err
	}

	return netlink.LinkSetGSOIPv4MaxSize(link, GSOMaxSize)
}

func haveIPv4MaxSize() bool {
	link, err := safenetlink.LinkByName(probeDevice)
	if err != nil {
		return false
	}
	if link.Attrs().GROIPv4MaxSize > 0 && link.Attrs().GSOIPv4MaxSize > 0 {
		return true
	}
	return false
}

func haveIPv6MaxSize() bool {
	link, err := safenetlink.LinkByName(probeDevice)
	if err != nil {
		return false
	}
	if link.Attrs().TSOMaxSize > 0 {
		return true
	}
	return false
}

func probeTSOMaxSize(log *slog.Logger, devices []string) int {
	maxSize := min(bigTCPGSOMaxSize, bigTCPGROMaxSize)
	for _, device := range devices {
		link, err := safenetlink.LinkByName(device)
		if err == nil {
			tso := link.Attrs().TSOMaxSize
			tsoMax := int(tso)
			if tsoMax > defaultGSOMaxSize && tsoMax < maxSize {
				log.Info("Lowering GRO/GSO max size",
					logfields.From, maxSize,
					logfields.To, tsoMax,
					logfields.Device, device,
				)
				maxSize = tsoMax
			}
		}
	}
	return maxSize
}

type params struct {
	cell.In

	Log          *slog.Logger
	DaemonConfig *option.DaemonConfig
	UserConfig   types.BigTCPUserConfig
	DB           *statedb.DB
	Devices      statedb.Table[*tables.Device]
}

func validateConfig(cfg types.BigTCPUserConfig, daemonCfg *option.DaemonConfig) error {
	if cfg.EnableIPv6BIGTCP || cfg.EnableIPv4BIGTCP {
		if daemonCfg.TunnelingEnabled() {
			return errors.New("BIG TCP is not supported in tunneling mode")
		}
		if daemonCfg.EncryptionEnabled() {
			return errors.New("BIG TCP is not supported with encryption enabled")
		}
		if daemonCfg.EnableHostLegacyRouting {
			return errors.New("BIG TCP is not supported with legacy host routing")
		}
	}
	return nil
}

func newBIGTCP(lc cell.Lifecycle, p params) (*Configuration, error) {
	if err := validateConfig(p.UserConfig, p.DaemonConfig); err != nil {
		return nil, err
	}
	cfg := newDefaultConfiguration(p.UserConfig)
	lc.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			return startBIGTCP(p, cfg)
		},
	})
	return cfg, nil
}

func startBIGTCP(p params, cfg *Configuration) error {
	var err error

	nativeDevices, _ := tables.SelectedDevices(p.Devices, p.DB.ReadTxn())
	deviceNames := tables.DeviceNames(nativeDevices)

	disableMsg := ""
	if len(deviceNames) == 0 {
		if p.UserConfig.EnableIPv4BIGTCP || p.UserConfig.EnableIPv6BIGTCP {
			p.Log.Warn("BIG TCP could not detect host devices. Disabling the feature.")
		}
		p.UserConfig.EnableIPv4BIGTCP = false
		p.UserConfig.EnableIPv6BIGTCP = false
		return nil
	}

	haveIPv4 := haveIPv4MaxSize()
	haveIPv6 := haveIPv6MaxSize()

	if !haveIPv4 {
		if p.UserConfig.EnableIPv4BIGTCP {
			p.Log.Warn("Cannot enable --" + types.EnableIPv4BIGTCPFlag + ", needs kernel 6.3 or newer")
		}
		p.UserConfig.EnableIPv4BIGTCP = false
	}
	if !haveIPv6 {
		if p.UserConfig.EnableIPv6BIGTCP {
			p.Log.Warn("Cannot enable --" + types.EnableIPv6BIGTCPFlag + ", needs kernel 5.19 or newer")
		}
		p.UserConfig.EnableIPv6BIGTCP = false
	}
	if !haveIPv4 && !haveIPv6 {
		return nil
	}

	if haveIPv4 {
		cfg.groIPv4MaxSize = defaultGROMaxSize
		cfg.gsoIPv4MaxSize = defaultGSOMaxSize
	}
	if haveIPv6 {
		cfg.groIPv6MaxSize = defaultGROMaxSize
		cfg.gsoIPv6MaxSize = defaultGSOMaxSize
	}

	if p.UserConfig.EnableIPv6BIGTCP || p.UserConfig.EnableIPv4BIGTCP {
		p.Log.Info("Setting up BIG TCP")
		tsoMax := probeTSOMaxSize(p.Log, deviceNames)
		if p.UserConfig.EnableIPv4BIGTCP && haveIPv4 {
			cfg.groIPv4MaxSize = tsoMax
			cfg.gsoIPv4MaxSize = tsoMax
		}
		if p.UserConfig.EnableIPv6BIGTCP && haveIPv6 {
			cfg.groIPv6MaxSize = tsoMax
			cfg.gsoIPv6MaxSize = tsoMax
		}
		disableMsg = ", disabling BIG TCP"
	}

	bigv6 := p.UserConfig.EnableIPv6BIGTCP
	bigv4 := p.UserConfig.EnableIPv4BIGTCP

	modifiedDevices := []string{}
	for _, device := range deviceNames {
		// We always add the device because we might do only a partial
		// modification and end up with an error, so best to be conservative
		// and always reset all on error.
		modifiedDevices = append(modifiedDevices, device)
		// For compatibility, the kernel will also update the net device's
		// {gso,gro}_ipv4_max_size, if the new size of {gso,gro}_max_size
		// isn't greater than 64KB. So it needs to set the IPv6 one first
		// as otherwise the IPv4 BIG TCP value will be reset.
		if haveIPv6 {
			err = setGROGSOIPv6MaxSize(p.Log, p.UserConfig, device,
				cfg.groIPv6MaxSize, cfg.gsoIPv6MaxSize)
			if err != nil {
				p.Log.Warn("Could not modify IPv6 gro_max_size and gso_max_size"+disableMsg,
					logfields.Device, device,
					logfields.Error, err)
				p.UserConfig.EnableIPv4BIGTCP = false
				p.UserConfig.EnableIPv6BIGTCP = false
				break
			}
			p.Log.Info("Setting IPv6",
				logfields.Device, device,
				logfields.GsoMaxSize, cfg.gsoIPv6MaxSize,
				logfields.GroMaxSize, cfg.groIPv6MaxSize,
			)
		}
		if haveIPv4 {
			err = setGROGSOIPv4MaxSize(p.Log, p.UserConfig, device,
				cfg.groIPv4MaxSize, cfg.gsoIPv4MaxSize)
			if err != nil {
				msg := "Could not modify IPv4 gro_max_size and gso_max_size" + disableMsg
				p.Log.Warn(msg,
					logfields.Device, device,
					logfields.Error, err,
				)
				p.UserConfig.EnableIPv4BIGTCP = false
				p.UserConfig.EnableIPv6BIGTCP = false
				break
			}
			p.Log.Info("Setting IPv4",
				logfields.Device, device,
				logfields.GsoMaxSize, cfg.gsoIPv4MaxSize,
				logfields.GroMaxSize, cfg.groIPv4MaxSize,
			)
		}
	}

	if err != nil {
		if haveIPv4 {
			cfg.groIPv4MaxSize = defaultGROMaxSize
			cfg.gsoIPv4MaxSize = defaultGSOMaxSize
		}
		if haveIPv6 {
			cfg.groIPv6MaxSize = defaultGROMaxSize
			cfg.gsoIPv6MaxSize = defaultGSOMaxSize
		}
		for _, device := range modifiedDevices {
			if bigv4 {
				err = setGROGSOIPv4MaxSize(p.Log, p.UserConfig, device,
					defaultGROMaxSize, defaultGSOMaxSize)
				if err != nil {
					p.Log.Warn("Could not reset IPv4 gro_max_size and gso_max_size",
						logfields.Device, device,
						logfields.Error, err,
					)
					continue
				}
				p.Log.Info("Resetting IPv4 gso_max_size and gro_max_size", logfields.Device, device)
			}
			if bigv6 {
				err = setGROGSOIPv6MaxSize(p.Log, p.UserConfig, device,
					defaultGROMaxSize, defaultGSOMaxSize)
				if err != nil {
					p.Log.Warn("Could not reset IPv6 gro_max_size and gso_max_size",
						logfields.Device, device,
						logfields.Error, err,
					)
					continue
				}
				p.Log.Info("Resetting IPv6 gso_max_size and gro_max_size", logfields.Device, device)
			}
		}
	}

	return nil
}
