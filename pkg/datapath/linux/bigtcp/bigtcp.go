// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bigtcp

import (
	"errors"
	"log/slog"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

const (
	defaultMaxSize = 65536
	bigTCPMaxSize  = 196608

	probeDevice = "lo"
)

var defaultUserConfig = types.BigTCPUserConfig{
	EnableIPv6BIGTCP:   false,
	EnableIPv4BIGTCP:   false,
	EnableTunnelBIGTCP: false,
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
		groIPv4MaxSize:   0,
		gsoIPv4MaxSize:   0,
		groIPv6MaxSize:   0,
		gsoIPv6MaxSize:   0,
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
func SetGROGSOIPv6MaxSize(log *slog.Logger, device string, GROMaxSize, GSOMaxSize int) error {
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
	// when that is not necessary (the current size matches the target size).
	if int(attrs.GROMaxSize) == GROMaxSize && int(attrs.GSOMaxSize) == GSOMaxSize {
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
func SetGROGSOIPv4MaxSize(log *slog.Logger, device string, GROMaxSize, GSOMaxSize int) error {
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
	// when that is not necessary (the current size matches the target size).
	if int(attrs.GROIPv4MaxSize) == GROMaxSize && int(attrs.GSOIPv4MaxSize) == GSOMaxSize {
		return nil
	}

	err = netlink.LinkSetGROIPv4MaxSize(link, GROMaxSize)
	if err != nil {
		return err
	}

	return netlink.LinkSetGSOIPv4MaxSize(link, GSOMaxSize)
}

// Probes whether the kernel supports BIG TCP IPv4.
func supportsBIGTCPIPv4(log *slog.Logger) bool {
	link, err := safenetlink.LinkByName(probeDevice)
	if err != nil {
		log.Warn("Failed to probe kernel support for BIG TCP IPv4")
		return false
	}
	// Kernel commit 9eefedd58ae1 ("net: add gso_ipv4_max_size and gro_ipv4_max_size per device").
	// Patch 09/10 of the series "net: support ipv4 big tcp".
	return link.Attrs().GROIPv4MaxSize > 0 && link.Attrs().GSOIPv4MaxSize > 0
}

// Probes whether the kernel supports BIG TCP IPv6.
func supportsBIGTCPIPv6(log *slog.Logger) bool {
	link, err := safenetlink.LinkByName(probeDevice)
	if err != nil {
		log.Warn("Failed to probe kernel support for BIG TCP IPv6")
		return false
	}
	// Kernel commit 89527be8d8d6 ("net: add IFLA_TSO_{MAX_SIZE|SEGS} attributes").
	// Patch 01/13 of the series "tcp: BIG TCP implementation".
	return link.Attrs().TSOMaxSize > 0
}

// Returns the current gso_max_size (IPv6), gso_ipv4_max_size (IPv4) and
// tso_max_size (the limit for both) for device.
// If gso_ipv4_max_size is not supported, fall back to gso_max_size.
// If tso_max_size is not supported, fall back to GSO_LEGACY_MAX_SIZE = 65536.
func getGSOMaxSize(log *slog.Logger, device string) (int, int, int) {
	link, err := safenetlink.LinkByName(device)
	if err != nil {
		log.Warn("Failed to probe gso_max_size and tso_max_size",
			logfields.Device, device,
		)
		return 0, 0, 0
	}
	gsoMaxSizeIPv6 := int(link.Attrs().GSOMaxSize)
	gsoMaxSizeIPv4 := int(link.Attrs().GSOIPv4MaxSize)
	if gsoMaxSizeIPv4 == 0 {
		// IFLA_GSO_IPV4_MAX_SIZE is at least MAX_TCP_HEADER + 1.
		// Assume old kernel without gso_ipv4_max_size.
		gsoMaxSizeIPv4 = defaultMaxSize
	}
	tsoMaxSize := int(link.Attrs().TSOMaxSize)
	if tsoMaxSize == 0 {
		// Assume old kernel without tso_max_size and return its limit.
		tsoMaxSize = defaultMaxSize
	}
	return gsoMaxSizeIPv6, gsoMaxSizeIPv4, tsoMaxSize
}

// Returns the current gro_max_size (IPv6), gro_ipv4_max_size (IPv4) and their
// limit for device.
// If gro_ipv4_max_size is not supported, fall back to gro_ipv4_max_size.
func getGROMaxSize(log *slog.Logger, device string) (int, int, int) {
	link, err := safenetlink.LinkByName(device)
	if err != nil {
		log.Warn("Failed to probe gro_max_size",
			logfields.Device, device,
		)
		return 0, 0, 0
	}
	groMaxSizeIPv6 := int(link.Attrs().GROMaxSize)
	groMaxSizeIPv4 := int(link.Attrs().GROIPv4MaxSize)
	if groMaxSizeIPv4 == 0 && link.Attrs().GSOIPv4MaxSize == 0 {
		// While gro_ipv4_max_size can be set to zero, gso_ipv4_max_size can't, and both
		// were added in the same kernel commit. Check gso_ipv4_max_size to determine
		// whether it's an old kernel without gro_ipv4_max_size.
		groMaxSizeIPv4 = defaultMaxSize
	}
	// The limit for gro_max_size is hardcoded in the kernel as GRO_MAX_SIZE = 8 * 65535.
	return groMaxSizeIPv6, groMaxSizeIPv4, 8 * 65535
}

type params struct {
	cell.In

	Log          *slog.Logger
	DaemonConfig *option.DaemonConfig
	UserConfig   types.BigTCPUserConfig
	IPsecConfig  types.IPsecConfig
	LBConfig     loadbalancer.Config
	DB           *statedb.DB
	Devices      statedb.Table[*tables.Device]
}

func validateConfig(cfg types.BigTCPUserConfig, daemonCfg *option.DaemonConfig, ipsecCfg types.IPsecConfig, dsrDispatch string) error {
	if cfg.EnableIPv6BIGTCP || cfg.EnableIPv4BIGTCP {
		// Check all configurations where Cilium creates tunnel devices
		// that don't support BIG TCP.
		if dsrDispatch == loadbalancer.DSRDispatchIPIP {
			return errors.New("bpf-lb-dsr-dispatch ipip creates IPIP tunnels that aren't compatible with BIG TCP")
		}
		if !cfg.EnableTunnelBIGTCP {
			if daemonCfg.TunnelingEnabled() {
				return errors.New("BIG TCP in tunneling mode requires pending kernel support and needs to be enabled by enable-tunnel-big-tcp")
			}
			if dsrDispatch != loadbalancer.DSRDispatchOption {
				return errors.New("bpf-lb-dsr-dispatch geneve requires pending kernel support and needs to be enabled by enable-tunnel-big-tcp")
			}
		}

		if ipsecCfg.Enabled() {
			return errors.New("BIG TCP is not supported with encryption enabled")
		}
		if daemonCfg.UnsafeDaemonConfigOption.EnableHostLegacyRouting {
			return errors.New("BIG TCP is not supported with legacy host routing")
		}
	}
	return nil
}

func newBIGTCP(lc cell.Lifecycle, p params) (*Configuration, error) {
	if err := validateConfig(p.UserConfig, p.DaemonConfig, p.IPsecConfig, p.LBConfig.DSRDispatch); err != nil {
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

type netdevParams struct {
	name           string
	gsoMaxSizeIPv6 int
	gsoMaxSizeIPv4 int
	groMaxSizeIPv6 int
	groMaxSizeIPv4 int
}

func startBIGTCP(p params, cfg *Configuration) error {
	var err error

	nativeDevices, _ := tables.SelectedDevices(p.Devices, p.DB.ReadTxn())
	deviceNames := tables.DeviceNames(nativeDevices)

	if p.UserConfig.EnableIPv4BIGTCP && !supportsBIGTCPIPv4(p.Log) {
		p.Log.Warn("Cannot enable --" + types.EnableIPv4BIGTCPFlag + ", needs kernel 6.3 or newer")
		p.UserConfig.EnableIPv4BIGTCP = false
	}
	if p.UserConfig.EnableIPv6BIGTCP && !supportsBIGTCPIPv6(p.Log) {
		p.Log.Warn("Cannot enable --" + types.EnableIPv6BIGTCPFlag + ", needs kernel 5.19 or newer")
		p.UserConfig.EnableIPv6BIGTCP = false
	}

	// Apply the following logic to set GSO and GRO max sizes for native
	// devices. Apply it separately for IPv6 and IPv4, IPv6 being first,
	// because backwards compatibility in the kernel adjusts the IPv4 values
	// if the IPv6 ones are set to 65536 or less.
	//
	// * If BIG TCP is enabled, find the smallest GSO/GRO IPv4/IPv6 limits
	// across all devices, additionally cap them at bigTCPMaxSize, and set
	// the max sizes to the resulting limits. Store them to be used by
	// tunnel netdevs later.
	//
	// * If BIG TCP is disabled, ensure that no devices have GSO/GRO
	// IPv4/IPv6 max sizes set to values bigger than 65536. That is, if it's
	// already bigger, lower it to 65536; if it's smaller, keep it at
	// admin's discretion, but find the lowest and store it to be used by
	// tunnel netdevs later.

	origParams := []netdevParams{}
	bigtcpGSOLimit := bigTCPMaxSize
	bigtcpGROLimit := bigTCPMaxSize
	lowestGSOMaxSizeIPv6 := defaultMaxSize
	lowestGSOMaxSizeIPv4 := defaultMaxSize
	lowestGROMaxSizeIPv6 := defaultMaxSize
	lowestGROMaxSizeIPv4 := defaultMaxSize
	for _, device := range deviceNames {
		gsoMaxSizeIPv6, gsoMaxSizeIPv4, gsoLimit := getGSOMaxSize(p.Log, device)
		groMaxSizeIPv6, groMaxSizeIPv4, groLimit := getGROMaxSize(p.Log, device)
		orig := netdevParams{
			name:           device,
			gsoMaxSizeIPv6: gsoMaxSizeIPv6,
			gsoMaxSizeIPv4: gsoMaxSizeIPv4,
			groMaxSizeIPv6: groMaxSizeIPv6,
			groMaxSizeIPv4: groMaxSizeIPv4,
		}
		origParams = append(origParams, orig)

		// In case of BIG TCP, calculate the highest max sizes allowed by all devices.
		if gsoLimit < bigtcpGSOLimit {
			bigtcpGSOLimit = gsoLimit
		}
		if groLimit < bigtcpGROLimit {
			bigtcpGROLimit = groLimit
		}

		// In case of non-BIG TCP, store the lowest max sizes to be used by the tunnel.
		if gsoMaxSizeIPv6 < lowestGSOMaxSizeIPv6 {
			lowestGSOMaxSizeIPv6 = gsoMaxSizeIPv6
		}
		if gsoMaxSizeIPv4 < lowestGSOMaxSizeIPv4 {
			lowestGSOMaxSizeIPv4 = gsoMaxSizeIPv4
		}
		if groMaxSizeIPv6 < lowestGROMaxSizeIPv6 {
			lowestGROMaxSizeIPv6 = groMaxSizeIPv6
		}
		if groMaxSizeIPv4 < lowestGROMaxSizeIPv4 {
			lowestGROMaxSizeIPv4 = groMaxSizeIPv4
		}
	}

	// Start modifying on the second pass, when the target value for BIG TCP
	// is known. Technically, the modifications for non-BIG TCP are possible
	// on the first pass, but we want to avoid adding the device to
	// modifiedParams twice if BIG TCP is enabled for one address family.
	modifiedParams := []netdevParams{}
	for _, device := range origParams {
		modified := false

		gsoMaxSizeIPv6 := device.gsoMaxSizeIPv6
		gsoMaxSizeIPv4 := device.gsoMaxSizeIPv4
		groMaxSizeIPv6 := device.groMaxSizeIPv6
		groMaxSizeIPv4 := device.groMaxSizeIPv4

		// For BIG TCP: set max sizes to the ones calculated above.
		// Roll back the changes on any failure, because we couldn't
		// enable the feature.
		// For non-BIG TCP: don't change max sizes set by the admin,
		// unless they are bigger than 65536. Continue on failures,
		// because we are not enabling BIG TCP.

		if p.UserConfig.EnableIPv6BIGTCP {
			p.Log.Info("Enabling BIG TCP IPv6",
				logfields.Device, device.name,
				logfields.GroMaxSize, bigtcpGROLimit,
				logfields.GsoMaxSize, bigtcpGSOLimit,
			)
			modified = true
			err = SetGROGSOIPv6MaxSize(p.Log, device.name, bigtcpGROLimit, bigtcpGSOLimit)
			if err != nil {
				p.Log.Warn("Could not change IPv6 gro_max_size and gso_max_size",
					logfields.Device, device.name,
					logfields.Error, err,
				)
				goto out
			}
		} else {
			change := false
			if gsoMaxSizeIPv6 > defaultMaxSize {
				gsoMaxSizeIPv6 = defaultMaxSize
				change = true
			}
			if groMaxSizeIPv6 > defaultMaxSize {
				groMaxSizeIPv6 = defaultMaxSize
				change = true
			}
			if change {
				p.Log.Info("BIG TCP IPv6 is disabled, but gro_max_size or gso_max_size is bigger than 65536: lowering",
					logfields.Device, device.name,
					logfields.GroMaxSize, device.groMaxSizeIPv6,
					logfields.GsoMaxSize, device.gsoMaxSizeIPv6,
				)
				modified = true
				err = SetGROGSOIPv6MaxSize(p.Log, device.name, groMaxSizeIPv6, gsoMaxSizeIPv6)
				if err != nil {
					p.Log.Warn("Could not change IPv6 gro_max_size and gso_max_size",
						logfields.Device, device.name,
						logfields.Error, err,
					)
					// Treat it as non-critical: we are not enabling BIG TCP.
					err = nil
				}
			}
		}

		if p.UserConfig.EnableIPv4BIGTCP {
			p.Log.Info("Enabling BIG TCP IPv4",
				logfields.Device, device.name,
				logfields.GroMaxSize, bigtcpGROLimit,
				logfields.GsoMaxSize, bigtcpGSOLimit,
			)
			modified = true
			err = SetGROGSOIPv4MaxSize(p.Log, device.name, bigtcpGROLimit, bigtcpGSOLimit)
			if err != nil {
				p.Log.Warn("Could not change IPv4 gro_ipv4_max_size and gso_ipv4_max_size",
					logfields.Device, device.name,
					logfields.Error, err,
				)
				goto out
			}
		} else {
			change := false
			if gsoMaxSizeIPv4 > defaultMaxSize {
				gsoMaxSizeIPv4 = defaultMaxSize
				change = true
			}
			if groMaxSizeIPv4 > defaultMaxSize {
				groMaxSizeIPv4 = defaultMaxSize
				change = true
			}
			if change {
				p.Log.Info("BIG TCP IPv4 is disabled, but gro_ipv4_max_size or gso_ipv4_max_size is bigger than 65536: lowering",
					logfields.Device, device.name,
					logfields.GroMaxSize, device.groMaxSizeIPv4,
					logfields.GsoMaxSize, device.gsoMaxSizeIPv4,
				)
				modified = true
				err = SetGROGSOIPv4MaxSize(p.Log, device.name, groMaxSizeIPv4, gsoMaxSizeIPv4)
				if err != nil {
					p.Log.Warn("Could not change IPv4 gro_ipv4_max_size or gso_ipv4_max_size",
						logfields.Device, device.name,
						logfields.Error, err,
					)
					// Treat it as non-critical: we are not enabling BIG TCP.
					err = nil
				}
			}
		}

	out:
		if modified {
			// Append once even if modified twice.
			modifiedParams = append(modifiedParams, device)
		}
		if err != nil {
			break
		}
	}

	if err != nil {
		p.Log.Info("An error occurred: trying to restore the original settings")

		p.UserConfig.EnableIPv6BIGTCP = false
		p.UserConfig.EnableIPv4BIGTCP = false

		for _, device := range slices.Backward(modifiedParams) {
			p.Log.Info("Restoring IPv6 gro_max_size and gso_max_size",
				logfields.Device, device.name,
				logfields.GroMaxSize, device.groMaxSizeIPv6,
				logfields.GsoMaxSize, device.gsoMaxSizeIPv6,
			)
			err = SetGROGSOIPv6MaxSize(p.Log, device.name,
				device.groMaxSizeIPv6, device.gsoMaxSizeIPv6)
			if err != nil {
				p.Log.Warn("Could not restore IPv6 gro_max_size or gso_max_size",
					logfields.Device, device.name,
					logfields.Error, err,
				)
			}

			p.Log.Info("Restoring IPv4 gro_ipv4_max_size and gso_ipv4_max_size",
				logfields.Device, device.name,
				logfields.GroMaxSize, device.groMaxSizeIPv4,
				logfields.GsoMaxSize, device.gsoMaxSizeIPv4,
			)
			err = SetGROGSOIPv4MaxSize(p.Log, device.name,
				device.groMaxSizeIPv4, device.gsoMaxSizeIPv4)
			if err != nil {
				p.Log.Warn("Could not restore IPv4 gro_ipv4_max_size or gso_ipv4_max_size",
					logfields.Device, device.name,
					logfields.Error, err,
				)
			}
		}
	}

	// Store the final values to be used by the tunnel, after it's known
	// whether the feature has been enabled successfully.
	if p.UserConfig.EnableIPv6BIGTCP {
		cfg.groIPv6MaxSize = bigtcpGROLimit
		cfg.gsoIPv6MaxSize = bigtcpGSOLimit
	} else {
		cfg.groIPv6MaxSize = lowestGROMaxSizeIPv6
		cfg.gsoIPv6MaxSize = lowestGSOMaxSizeIPv6
	}
	if p.UserConfig.EnableIPv4BIGTCP {
		cfg.groIPv4MaxSize = bigtcpGROLimit
		cfg.gsoIPv4MaxSize = bigtcpGSOLimit
	} else {
		cfg.groIPv4MaxSize = lowestGROMaxSizeIPv4
		cfg.gsoIPv4MaxSize = lowestGSOMaxSizeIPv4
	}

	return err
}
