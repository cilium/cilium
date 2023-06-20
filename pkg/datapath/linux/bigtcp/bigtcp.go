// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bigtcp

import (
	"github.com/vishvananda/netlink"

	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	"github.com/cilium/cilium/pkg/math"
	"github.com/cilium/cilium/pkg/option"
)

const (
	defaultGROMaxSize = 65536
	defaultGSOMaxSize = 65536

	bigTCPGROMaxSize = 196608
	bigTCPGSOMaxSize = 196608

	probeDevice = "lo"
)

// Configuration is a BIG TCP configuration as returned by NewConfiguration
type Configuration struct {
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
func setGROGSOIPv6MaxSize(device string, GROMaxSize, GSOMaxSize int) error {
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

// If an error is returned the caller is responsible for rolling back
// any partial changes.
func setGROGSOIPv4MaxSize(device string, GROMaxSize, GSOMaxSize int) error {
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
		(!option.Config.EnableIPv4BIGTCP &&
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

func probeTSOMaxSize() int {
	maxSize := math.IntMin(bigTCPGSOMaxSize, bigTCPGROMaxSize)
	for _, device := range option.Config.GetDevices() {
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

func InitBIGTCP(bigTCPConfig *Configuration) {
	var err error

	if option.Config.DryMode {
		return
	}

	disableMsg := ""
	if len(option.Config.GetDevices()) == 0 {
		if option.Config.EnableIPv4BIGTCP || option.Config.EnableIPv6BIGTCP {
			log.Warn("BIG TCP could not detect host devices. Disabling the feature.")
		}
		option.Config.EnableIPv4BIGTCP = false
		option.Config.EnableIPv6BIGTCP = false
		return
	}

	haveIPv4 := haveIPv4MaxSize()
	haveIPv6 := haveIPv6MaxSize()

	if !haveIPv4 {
		if option.Config.EnableIPv4BIGTCP {
			log.Warnf("Cannot enable --%s, needs kernel 6.3 or newer",
				option.EnableIPv4BIGTCP)
		}
		option.Config.EnableIPv4BIGTCP = false
	}
	if !haveIPv6 {
		if option.Config.EnableIPv6BIGTCP {
			log.Warnf("Cannot enable --%s, needs kernel 5.19 or newer",
				option.EnableIPv6BIGTCP)
		}
		option.Config.EnableIPv6BIGTCP = false
	}
	if !haveIPv4 && !haveIPv6 {
		return
	}

	if haveIPv4 {
		bigTCPConfig.groIPv4MaxSize = defaultGROMaxSize
		bigTCPConfig.gsoIPv4MaxSize = defaultGSOMaxSize
	}
	if haveIPv6 {
		bigTCPConfig.groIPv6MaxSize = defaultGROMaxSize
		bigTCPConfig.gsoIPv6MaxSize = defaultGSOMaxSize
	}

	if option.Config.EnableIPv6BIGTCP || option.Config.EnableIPv4BIGTCP {
		if option.Config.DatapathMode != datapathOption.DatapathModeVeth {
			log.Fatal("BIG TCP is supported only in veth datapath mode")
		}
		if option.Config.TunnelingEnabled() {
			log.Fatal("BIG TCP is not supported in tunneling mode")
		}
		if option.Config.EncryptionEnabled() {
			log.Fatal("BIG TCP is not supported with encryption enabled")
		}
		if option.Config.EnableHostLegacyRouting {
			log.Fatal("BIG TCP is not supported with legacy host routing")
		}

		log.Infof("Setting up BIG TCP")
		tsoMax := probeTSOMaxSize()
		if option.Config.EnableIPv4BIGTCP && haveIPv4 {
			bigTCPConfig.groIPv4MaxSize = tsoMax
			bigTCPConfig.gsoIPv4MaxSize = tsoMax
		}
		if option.Config.EnableIPv6BIGTCP && haveIPv6 {
			bigTCPConfig.groIPv6MaxSize = tsoMax
			bigTCPConfig.gsoIPv6MaxSize = tsoMax
		}
		disableMsg = ", disabling BIG TCP"
	}

	bigv6 := option.Config.EnableIPv6BIGTCP
	bigv4 := option.Config.EnableIPv4BIGTCP

	modifiedDevices := []string{}
	for _, device := range option.Config.GetDevices() {
		// We always add the device because we might do only a partial
		// modification and end up with an error, so best to be conservative
		// and always reset all on error.
		modifiedDevices = append(modifiedDevices, device)
		// For compatibility, the kernel will also update the net device's
		// {gso,gro}_ipv4_max_size, if the new size of {gso,gro}_max_size
		// isn't greater than 64KB. So it needs to set the IPv6 one first
		// as otherwise the IPv4 BIG TCP value will be reset.
		if haveIPv6 {
			err = setGROGSOIPv6MaxSize(device,
				bigTCPConfig.groIPv6MaxSize, bigTCPConfig.gsoIPv6MaxSize)
			if err != nil {
				log.WithError(err).WithField("device", device).Warnf("Could not modify IPv6 gro_max_size and gso_max_size%s",
					disableMsg)
				option.Config.EnableIPv4BIGTCP = false
				option.Config.EnableIPv6BIGTCP = false
				break
			}
			log.WithField("device", device).Infof("Setting IPv6 gso_max_size to %d and gro_max_size to %d",
				bigTCPConfig.gsoIPv6MaxSize, bigTCPConfig.groIPv6MaxSize)
		}
		if haveIPv4 {
			err = setGROGSOIPv4MaxSize(device,
				bigTCPConfig.groIPv4MaxSize, bigTCPConfig.gsoIPv4MaxSize)
			if err != nil {
				log.WithError(err).WithField("device", device).Warnf("Could not modify IPv4 gro_max_size and gso_max_size%s",
					disableMsg)
				option.Config.EnableIPv4BIGTCP = false
				option.Config.EnableIPv6BIGTCP = false
				break
			}
			log.WithField("device", device).Infof("Setting IPv4 gso_max_size to %d and gro_max_size to %d",
				bigTCPConfig.gsoIPv4MaxSize, bigTCPConfig.groIPv4MaxSize)
		}
	}

	if err != nil {
		if haveIPv4 {
			bigTCPConfig.groIPv4MaxSize = defaultGROMaxSize
			bigTCPConfig.gsoIPv4MaxSize = defaultGSOMaxSize
		}
		if haveIPv6 {
			bigTCPConfig.groIPv6MaxSize = defaultGROMaxSize
			bigTCPConfig.gsoIPv6MaxSize = defaultGSOMaxSize
		}
		for _, device := range modifiedDevices {
			if bigv4 {
				err = setGROGSOIPv4MaxSize(device,
					defaultGROMaxSize, defaultGSOMaxSize)
				if err != nil {
					log.WithError(err).WithField("device", device).Warn("Could not reset IPv4 gro_max_size and gso_max_size")
					continue
				}
				log.WithField("device", device).Info("Resetting IPv4 gso_max_size and gro_max_size")
			}
			if bigv6 {
				err = setGROGSOIPv6MaxSize(device,
					defaultGROMaxSize, defaultGSOMaxSize)
				if err != nil {
					log.WithError(err).WithField("device", device).Warn("Could not reset IPv6 gro_max_size and gso_max_size")
					continue
				}
				log.WithField("device", device).Info("Resetting IPv6 gso_max_size and gro_max_size")
			}
		}
	}
}
