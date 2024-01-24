// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bigtcp

import (
	"errors"

	"github.com/spf13/pflag"
	"github.com/vishvananda/netlink"

	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/math"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/statedb"
)

const (
	defaultGROMaxSize = 65536
	defaultGSOMaxSize = 65536

	bigTCPGROMaxSize = 196608
	bigTCPGSOMaxSize = 196608

	probeDevice = "lo"

	EnableIPv4BIGTCPFlag = "enable-ipv4-big-tcp"
	EnableIPv6BIGTCPFlag = "enable-ipv6-big-tcp"
)

// UserConfig are the configuration flags that the user can modify.
type UserConfig struct {
	// EnableIPv6BIGTCP enables IPv6 BIG TCP (larger GSO/GRO limits) for the node including pods.
	EnableIPv6BIGTCP bool

	// EnableIPv4BIGTCP enables IPv4 BIG TCP (larger GSO/GRO limits) for the node including pods.
	EnableIPv4BIGTCP bool
}

var defaultUserConfig = UserConfig{
	EnableIPv6BIGTCP: false,
	EnableIPv4BIGTCP: false,
}

func (def UserConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool(EnableIPv4BIGTCPFlag, def.EnableIPv4BIGTCP, "Enable IPv4 BIG TCP option which increases device's maximum GRO/GSO limits for IPv4")
	flags.Bool(EnableIPv6BIGTCPFlag, def.EnableIPv6BIGTCP, "Enable IPv6 BIG TCP option which increases device's maximum GRO/GSO limits for IPv6")
}

var Cell = cell.Module(
	"bigtcp",
	"BIG TCP support",

	cell.Config(defaultUserConfig),
	cell.Provide(newBIGTCP),
	cell.Invoke(func(*Configuration) {}),
)

func newDefaultConfiguration(userConfig UserConfig) *Configuration {
	return &Configuration{
		UserConfig:     userConfig,
		groIPv4MaxSize: defaultGROMaxSize,
		gsoIPv4MaxSize: defaultGSOMaxSize,
		groIPv6MaxSize: defaultGROMaxSize,
		gsoIPv6MaxSize: defaultGSOMaxSize,
	}
}

// Configuration is the BIG TCP configuration. The values are finalized after
// BIG TCP has started and must not be read before that.
type Configuration struct {
	UserConfig

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
func setGROGSOIPv6MaxSize(userConfig UserConfig, device string, GROMaxSize, GSOMaxSize int) error {
	link, err := netlink.LinkByName(device)
	if err != nil {
		log.WithError(err).WithField("device", device).Warn("Link does not exist")
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
func setGROGSOIPv4MaxSize(userConfig UserConfig, device string, GROMaxSize, GSOMaxSize int) error {
	link, err := netlink.LinkByName(device)
	if err != nil {
		log.WithError(err).WithField("device", device).Warn("Link does not exist")
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
	link, err := netlink.LinkByName(probeDevice)
	if err != nil {
		return false
	}
	if link.Attrs().GROIPv4MaxSize > 0 && link.Attrs().GSOIPv4MaxSize > 0 {
		return true
	}
	return false
}

func haveIPv6MaxSize() bool {
	link, err := netlink.LinkByName(probeDevice)
	if err != nil {
		return false
	}
	if link.Attrs().TSOMaxSize > 0 {
		return true
	}
	return false
}

func probeTSOMaxSize(devices []string) int {
	maxSize := math.IntMin(bigTCPGSOMaxSize, bigTCPGROMaxSize)
	for _, device := range devices {
		link, err := netlink.LinkByName(device)
		if err == nil {
			tso := link.Attrs().TSOMaxSize
			tsoMax := int(tso)
			if tsoMax > defaultGSOMaxSize && tsoMax < maxSize {
				log.WithField("device", device).Infof("Lowering GRO/GSO max size from %d to %d", maxSize, tsoMax)
				maxSize = tsoMax
			}
		}
	}
	return maxSize
}

type params struct {
	cell.In

	DaemonConfig *option.DaemonConfig
	UserConfig   UserConfig
	DB           *statedb.DB
	Devices      statedb.Table[*tables.Device]
}

func validateConfig(cfg UserConfig, daemonCfg *option.DaemonConfig) error {
	if cfg.EnableIPv6BIGTCP || cfg.EnableIPv4BIGTCP {
		if daemonCfg.DatapathMode != datapathOption.DatapathModeVeth {
			return errors.New("BIG TCP is supported only in veth datapath mode")
		}
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
			log.Warn("BIG TCP could not detect host devices. Disabling the feature.")
		}
		p.UserConfig.EnableIPv4BIGTCP = false
		p.UserConfig.EnableIPv6BIGTCP = false
		return nil
	}

	haveIPv4 := haveIPv4MaxSize()
	haveIPv6 := haveIPv6MaxSize()

	if !haveIPv4 {
		if p.UserConfig.EnableIPv4BIGTCP {
			log.Warnf("Cannot enable --%s, needs kernel 6.3 or newer",
				EnableIPv4BIGTCPFlag)
		}
		p.UserConfig.EnableIPv4BIGTCP = false
	}
	if !haveIPv6 {
		if p.UserConfig.EnableIPv6BIGTCP {
			log.Warnf("Cannot enable --%s, needs kernel 5.19 or newer",
				EnableIPv6BIGTCPFlag)
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
		log.Infof("Setting up BIG TCP")
		tsoMax := probeTSOMaxSize(deviceNames)
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
			err = setGROGSOIPv6MaxSize(p.UserConfig, device,
				cfg.groIPv6MaxSize, cfg.gsoIPv6MaxSize)
			if err != nil {
				log.WithError(err).WithField("device", device).Warnf("Could not modify IPv6 gro_max_size and gso_max_size%s",
					disableMsg)
				p.UserConfig.EnableIPv4BIGTCP = false
				p.UserConfig.EnableIPv6BIGTCP = false
				break
			}
			log.WithField("device", device).Infof("Setting IPv6 gso_max_size to %d and gro_max_size to %d",
				cfg.gsoIPv6MaxSize, cfg.groIPv6MaxSize)
		}
		if haveIPv4 {
			err = setGROGSOIPv4MaxSize(p.UserConfig, device,
				cfg.groIPv4MaxSize, cfg.gsoIPv4MaxSize)
			if err != nil {
				log.WithError(err).WithField("device", device).Warnf("Could not modify IPv4 gro_max_size and gso_max_size%s",
					disableMsg)
				p.UserConfig.EnableIPv4BIGTCP = false
				p.UserConfig.EnableIPv6BIGTCP = false
				break
			}
			log.WithField("device", device).Infof("Setting IPv4 gso_max_size to %d and gro_max_size to %d",
				cfg.gsoIPv4MaxSize, cfg.groIPv4MaxSize)
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
				err = setGROGSOIPv4MaxSize(p.UserConfig, device,
					defaultGROMaxSize, defaultGSOMaxSize)
				if err != nil {
					log.WithError(err).WithField("device", device).Warn("Could not reset IPv4 gro_max_size and gso_max_size")
					continue
				}
				log.WithField("device", device).Info("Resetting IPv4 gso_max_size and gro_max_size")
			}
			if bigv6 {
				err = setGROGSOIPv6MaxSize(p.UserConfig, device,
					defaultGROMaxSize, defaultGSOMaxSize)
				if err != nil {
					log.WithError(err).WithField("device", device).Warn("Could not reset IPv6 gro_max_size and gso_max_size")
					continue
				}
				log.WithField("device", device).Info("Resetting IPv6 gso_max_size and gro_max_size")
			}
		}
	}

	return nil
}
