// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bigtcp

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	"github.com/cilium/cilium/pkg/option"
)

const (
	defaultGROMaxSize = 65536
	defaultGSOMaxSize = 65536

	bigTCPGROMaxSize = 196608
	bigTCPGSOMaxSize = 196608
)

// Configuration is a BIG TCP configuration as returned by NewConfiguration
type Configuration struct {
	// gsoMaxSize is the GSO maximum size used when configuring devices
	//
	// Note that this is a singleton for the process including this
	// package. This means, for instance, that when using this from the
	// ``pkg/plugins/*`` sources, it will not respect the settings
	// configured inside the ``daemon/``.
	gsoMaxSize int

	// groMaxSize is the GRO maximum size used when configuring devices
	//
	// Note that this is a singleton for the process including this
	// package. This means, for instance, that when using this from the
	// ``pkg/plugins/*`` sources, it will not respect the settings
	// configured inside the ``daemon/``.
	groMaxSize int
}

func (c *Configuration) GetGROMaxSize() int {
	return c.groMaxSize
}

func (c *Configuration) GetGSOMaxSize() int {
	return c.gsoMaxSize
}

// if an error is returned the caller is responsible for rolling back
// any partial changes
func setGROGSOMaxSize(device string, GROMaxSize, GSOMaxSize int) error {
	link, err := netlink.LinkByName(device)
	if err != nil {
		log.WithError(err).WithField("device", device).Warn("Link does not exist")
		return nil
	}

	attrs := link.Attrs()
	// the check below is needed to avoid trying to change GSO/GRO max sizes
	// when that is not necessary (e.g. BIG TCP was never enabled or current
	// size matches the target size we need)
	if (int(attrs.GROMaxSize) == GROMaxSize && int(attrs.GSOMaxSize) == GSOMaxSize) ||
		(!option.Config.EnableIPv6BIGTCP &&
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

func InitBIGTCP(bigTCPConfig *Configuration) {
	var err error

	if option.Config.DryMode {
		return
	}

	if len(option.Config.GetDevices()) == 0 {
		if option.Config.EnableIPv6BIGTCP {
			log.Warn("IPv6 BIG TCP could not detect host devices. Disabling the feature.")
		}
		option.Config.EnableIPv6BIGTCP = false
		return
	}

	if probes.HaveProgramHelper(ebpf.SchedCLS, asm.FnDynptrData) != nil {
		if option.Config.EnableIPv6BIGTCP {
			log.Warnf("Cannot enable --%s, needs kernel 5.19 or newer",
				option.EnableIPv6BIGTCP)
		}
		option.Config.EnableIPv6BIGTCP = false
		return
	}

	disableMsg := ""
	bigTCPConfig.groMaxSize = defaultGROMaxSize
	bigTCPConfig.gsoMaxSize = defaultGSOMaxSize
	if option.Config.EnableIPv6BIGTCP {
		if option.Config.DatapathMode != datapathOption.DatapathModeVeth {
			log.Fatal("IPv6 BIG TCP is supported only in veth datapath mode")
		}
		if option.Config.TunnelingEnabled() {
			log.Fatal("IPv6 BIG TCP is not supported in tunneling mode")
		}
		if option.Config.EncryptionEnabled() {
			log.Fatal("IPv6 BIG TCP is not supported with encryption enabled")
		}
		if option.Config.EnableHostLegacyRouting {
			log.Fatal("IPv6 BIG TCP is not supported with legacy host routing")
		}

		log.Info("Setting up IPv6 BIG TCP")
		bigTCPConfig.groMaxSize = bigTCPGROMaxSize
		bigTCPConfig.gsoMaxSize = bigTCPGSOMaxSize
		disableMsg = ", disabling BIG TCP"
	}

	modifiedDevices := []string{}
	for _, device := range option.Config.GetDevices() {
		// we always add the device because we might do only a partial
		// modification and end up with an error, so best to be conservative
		// and always reset all on error
		modifiedDevices = append(modifiedDevices, device)
		err = setGROGSOMaxSize(device, bigTCPConfig.groMaxSize, bigTCPConfig.gsoMaxSize)
		if err != nil {
			log.WithError(err).WithField("device", device).Warnf("Could not modify gro_max_size and gso_max_size%s", disableMsg)
			option.Config.EnableIPv6BIGTCP = false
			break
		}
		log.WithField("device", device).Infof("Setting gso_max_size to %d and gro_max_size to %d",
			bigTCPConfig.gsoMaxSize, bigTCPConfig.groMaxSize)
	}

	if err != nil {
		bigTCPConfig.groMaxSize = defaultGROMaxSize
		bigTCPConfig.gsoMaxSize = defaultGSOMaxSize
		for _, device := range modifiedDevices {
			err = setGROGSOMaxSize(device, defaultGROMaxSize,
				defaultGSOMaxSize)
			if err != nil {
				log.WithError(err).WithField("device", device).Warn("Could not reset gro_max_size and gso_max_size")
				continue
			}
			log.WithField("device", device).Info("Resetting gso_max_size and gro_max_size")
		}
	}
}
