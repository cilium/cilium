// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metadata

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// AWS interface pattern prefix
	awsInterfacePrefix = "aws"
)

// ENIInterface represents an AWS ENI with its metadata
type ENIInterface struct {
	InterfaceID string `json:"interfaceId"`
	DeviceIndex int    `json:"deviceIndex"`
	PrivateIP   string `json:"privateIp"`
	MACAddress  string `json:"macAddress"`
	IfName      string `json:"ifname"`
}

// ENIDetector handles AWS-specific ENI detection using IMDS
type ENIDetector struct {
	logger    *slog.Logger
	client    *metadataClient
	eniLister ENILinkLister
}

// ENILinkLister is an interface for finding network interfaces by MAC address
// This allows for dependency injection in tests
type ENILinkLister interface {
	GetInterfaceNameByMAC(mac string) (string, error)
}

// ENILister implements ENILinkLister using netlink to find interfaces by MAC address
type ENILister struct{}

// NewENILister creates a new ENILister
func NewENILister() *ENILister {
	return &ENILister{}
}

// GetInterfaceNameByMAC finds the system interface name for a given MAC address
func (e *ENILister) GetInterfaceNameByMAC(macStr string) (string, error) {
	links, err := safenetlink.LinkList()
	if err != nil {
		return "", fmt.Errorf("failed to list interfaces: %w", err)
	}

	// Normalize MAC address format
	targetMAC := strings.ToLower(strings.ReplaceAll(macStr, "-", ":"))

	for _, link := range links {
		if link.Attrs().HardwareAddr == nil {
			continue
		}

		linkMAC := strings.ToLower(link.Attrs().HardwareAddr.String())
		if linkMAC == targetMAC {
			return link.Attrs().Name, nil
		}
	}

	return "", fmt.Errorf("no interface found with MAC %s", macStr)
}

// NewENIDetector creates a new AWS ENI detector
func NewENIDetector(ctx context.Context, logger *slog.Logger, eniLister ENILinkLister) (*ENIDetector, error) {
	client, err := NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create IMDS client: %w", err)
	}

	return &ENIDetector{
		logger:    logger,
		client:    client,
		eniLister: eniLister,
	}, nil
}

// IsAWSPattern checks if the given pattern is an AWS device index pattern (aws0, aws1, etc.)
func IsAWSPattern(pattern string) (bool, int) {
	if !strings.HasPrefix(pattern, awsInterfacePrefix) {
		return false, -1
	}

	suffix := strings.TrimPrefix(pattern, awsInterfacePrefix)
	if suffix == "" || suffix == "+" {
		// "aws" or "aws+" pattern - matches all AWS interfaces
		return true, -1
	}

	// Parse device index (e.g., "aws0", "aws1")
	var deviceIndex int
	_, err := fmt.Sscanf(suffix, "%d", &deviceIndex)
	if err != nil {
		return false, -1
	}

	return true, deviceIndex
}

// DetectInterfaces queries AWS IMDS and matches ENIs to system interfaces
func (d *ENIDetector) DetectInterfaces(ctx context.Context) ([]ENIInterface, error) {
	// Get list of MAC addresses from IMDS
	macs, err := d.getENIMACAddresses(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get ENI MAC addresses: %w", err)
	}

	var enis []ENIInterface
	for _, mac := range macs {
		eni, err := d.getENIDetails(ctx, mac)
		if err != nil {
			d.logger.Warn("Failed to get details for ENI",
				logfields.MACAddr, mac,
				logfields.Error, err)
			continue
		}

		// Match MAC address to system interface name
		ifname, err := d.eniLister.GetInterfaceNameByMAC(eni.MACAddress)
		if err != nil {
			d.logger.Warn("Failed to find interface for MAC",
				logfields.MACAddr, eni.MACAddress,
				logfields.Error, err)
			continue
		}

		eni.IfName = ifname
		enis = append(enis, eni)

		d.logger.Debug("Detected AWS ENI",
			logfields.ENI, eni.InterfaceID,
			logfields.Device, eni.DeviceIndex,
			logfields.Interface, eni.IfName,
			logfields.MACAddr, eni.MACAddress)
	}

	return enis, nil
}

// ResolveAWSPattern resolves an AWS pattern (aws0, aws1, aws+) to actual interface names
func (d *ENIDetector) ResolveAWSPattern(ctx context.Context, pattern string) ([]string, error) {
	isAWS, deviceIndex := IsAWSPattern(pattern)
	if !isAWS {
		return nil, fmt.Errorf("not an AWS pattern: %s", pattern)
	}

	enis, err := d.DetectInterfaces(ctx)
	if err != nil {
		return nil, err
	}

	var interfaces []string
	for _, eni := range enis {
		// If deviceIndex is -1, match all interfaces (aws+ pattern)
		// Otherwise, match specific device index
		if deviceIndex == -1 || eni.DeviceIndex == deviceIndex {
			interfaces = append(interfaces, eni.IfName)
		}
	}

	if len(interfaces) == 0 {
		return nil, fmt.Errorf("no interfaces found for pattern %s", pattern)
	}

	return interfaces, nil
}

// getENIMACAddresses retrieves all ENI MAC addresses from IMDS
func (d *ENIDetector) getENIMACAddresses(ctx context.Context) ([]string, error) {
	resp, err := getMetadata(ctx, d.client.client, "network/interfaces/macs/")
	if err != nil {
		return nil, fmt.Errorf("IMDS request failed: %w", err)
	}

	// Response is newline-separated list of MACs with trailing slashes
	lines := strings.Split(strings.TrimSpace(resp), "\n")
	var macs []string
	for _, line := range lines {
		mac := strings.TrimSuffix(strings.TrimSpace(line), "/")
		if mac != "" {
			macs = append(macs, mac)
		}
	}

	return macs, nil
}

// getENIDetails retrieves ENI details for a specific MAC address
func (d *ENIDetector) getENIDetails(ctx context.Context, mac string) (ENIInterface, error) {
	basePath := fmt.Sprintf("network/interfaces/macs/%s/", mac)

	// Query interface details
	interfaceID, err := getMetadata(ctx, d.client.client, basePath+"interface-id")
	if err != nil {
		return ENIInterface{}, fmt.Errorf("failed to get interface-id: %w", err)
	}

	deviceIndexStr, err := getMetadata(ctx, d.client.client, basePath+"device-number")
	if err != nil {
		return ENIInterface{}, fmt.Errorf("failed to get device-number: %w", err)
	}

	privateIP, err := getMetadata(ctx, d.client.client, basePath+"local-ipv4s")
	if err != nil {
		return ENIInterface{}, fmt.Errorf("failed to get local-ipv4s: %w", err)
	}

	var deviceIndex int
	_, err = fmt.Sscanf(deviceIndexStr, "%d", &deviceIndex)
	if err != nil {
		return ENIInterface{}, fmt.Errorf("invalid device-number: %w", err)
	}

	// Take first IP if multiple are listed
	privateIP = strings.Split(privateIP, "\n")[0]

	return ENIInterface{
		InterfaceID: interfaceID,
		DeviceIndex: deviceIndex,
		PrivateIP:   privateIP,
		MACAddress:  mac,
	}, nil
}

// IsRunningOnAWS checks if the instance is running on AWS by attempting to reach IMDS
func IsRunningOnAWS(ctx context.Context) bool {
	client, err := NewClient(ctx)
	if err != nil {
		return false
	}

	_, err = getMetadata(ctx, client.client, "instance-id")
	return err == nil
}

// MarshalENIList converts ENIInterface list to JSON for logging
func MarshalENIList(enis []ENIInterface) string {
	data, err := json.Marshal(enis)
	if err != nil {
		return "[]"
	}
	return string(data)
}

// ResolvePatterns resolves AWS-specific patterns (aws0, aws1, aws+) in a list of
// interface/device names to actual system interface names by querying AWS IMDS.
// Non-AWS patterns are returned unchanged. This is the main entry point for both
// iptables masquerading and BPF device selection.
func ResolvePatterns(ctx context.Context, logger *slog.Logger, patterns []string, eniLister ENILinkLister) []string {
	var resolved []string

	// Check if there are any AWS patterns first
	hasAWSPattern := false
	for _, pattern := range patterns {
		if isAWS, _ := IsAWSPattern(pattern); isAWS {
			hasAWSPattern = true
			break
		}
	}

	// Only create detector if we have AWS patterns
	var detector *ENIDetector
	if hasAWSPattern {
		var err error
		detector, err = NewENIDetector(ctx, logger, eniLister)
		if err != nil {
			logger.Warn("Failed to create ENI detector, AWS patterns will not be resolved",
				logfields.Error, err)
			// Return patterns unchanged
			return patterns
		}
	}

	for _, pattern := range patterns {
		isAWS, _ := IsAWSPattern(pattern)
		if !isAWS {
			// Not an AWS pattern, keep as-is
			resolved = append(resolved, pattern)
			continue
		}

		// Resolve AWS pattern to actual interface names
		awsInterfaces, err := detector.ResolveAWSPattern(ctx, pattern)
		if err != nil {
			logger.Warn("Failed to resolve AWS pattern, keeping original",
				logfields.MatchPattern, pattern,
				logfields.Error, err)
			resolved = append(resolved, pattern)
			continue
		}

		logger.Info("Resolved AWS pattern",
			logfields.MatchPattern, pattern,
			logfields.Devices, strings.Join(awsInterfaces, ", "))

		resolved = append(resolved, awsInterfaces...)
	}

	return resolved
}
