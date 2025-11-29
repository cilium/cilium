// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package aws

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// AWS Instance Metadata Service (IMDS) endpoint
	imdsBaseURL = "http://169.254.169.254/latest/meta-data"
	
	// HTTP timeout for IMDS requests
	imdsTimeout = 2 * time.Second
	
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

// InterfaceDetector handles AWS-specific interface detection
type InterfaceDetector struct {
	logger *slog.Logger
	client *http.Client
}

// NewInterfaceDetector creates a new AWS interface detector
func NewInterfaceDetector(logger *slog.Logger) *InterfaceDetector {
	return &InterfaceDetector{
		logger: logger,
		client: &http.Client{
			Timeout: imdsTimeout,
		},
	}
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
func (d *InterfaceDetector) DetectInterfaces() ([]ENIInterface, error) {
	// Get list of MAC addresses from IMDS
	macs, err := d.getENIMACAddresses()
	if err != nil {
		return nil, fmt.Errorf("failed to get ENI MAC addresses: %w", err)
	}
	
	var enis []ENIInterface
	for _, mac := range macs {
		eni, err := d.getENIDetails(mac)
		if err != nil {
			d.logger.Warn("Failed to get details for ENI",
				logfields.MACAddr, mac,
				logfields.Error, err)
			continue
		}
		
		// Match MAC address to system interface name
		ifname, err := d.getInterfaceNameByMAC(eni.MACAddress)
		if err != nil {
			d.logger.Warn("Failed to find interface for MAC",
				logfields.MACAddr, eni.MACAddress,
				logfields.Error, err)
			continue
		}
		
		eni.IfName = ifname
		enis = append(enis, eni)
		
		d.logger.Debug("Detected AWS ENI",
			"interfaceId", eni.InterfaceID,
			"deviceIndex", eni.DeviceIndex,
			"ifname", eni.IfName,
			logfields.MACAddr, eni.MACAddress)
	}
	
	return enis, nil
}

// ResolveAWSPattern resolves an AWS pattern (aws0, aws1, aws+) to actual interface names
func (d *InterfaceDetector) ResolveAWSPattern(pattern string) ([]string, error) {
	isAWS, deviceIndex := IsAWSPattern(pattern)
	if !isAWS {
		return nil, fmt.Errorf("not an AWS pattern: %s", pattern)
	}
	
	enis, err := d.DetectInterfaces()
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
func (d *InterfaceDetector) getENIMACAddresses() ([]string, error) {
	url := fmt.Sprintf("%s/network/interfaces/macs/", imdsBaseURL)
	resp, err := d.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("IMDS request failed: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("IMDS returned status %d", resp.StatusCode)
	}
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read IMDS response: %w", err)
	}
	
	// Response is newline-separated list of MACs with trailing slashes
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
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
func (d *InterfaceDetector) getENIDetails(mac string) (ENIInterface, error) {
	baseURL := fmt.Sprintf("%s/network/interfaces/macs/%s/", imdsBaseURL, mac)
	
	// Query interface details
	interfaceID, err := d.imdsGet(baseURL + "interface-id")
	if err != nil {
		return ENIInterface{}, fmt.Errorf("failed to get interface-id: %w", err)
	}
	
	deviceIndexStr, err := d.imdsGet(baseURL + "device-number")
	if err != nil {
		return ENIInterface{}, fmt.Errorf("failed to get device-number: %w", err)
	}
	
	privateIP, err := d.imdsGet(baseURL + "local-ipv4s")
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

// imdsGet performs a simple GET request to IMDS
func (d *InterfaceDetector) imdsGet(url string) (string, error) {
	resp, err := d.client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	
	return strings.TrimSpace(string(body)), nil
}

// getInterfaceNameByMAC finds the system interface name for a given MAC address
func (d *InterfaceDetector) getInterfaceNameByMAC(macStr string) (string, error) {
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

// IsRunningOnAWS checks if the instance is running on AWS by attempting to reach IMDS
func IsRunningOnAWS() bool {
	client := &http.Client{
		Timeout: 500 * time.Millisecond,
	}
	
	resp, err := client.Get(imdsBaseURL + "/instance-id")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	return resp.StatusCode == http.StatusOK
}

// MarshalJSON converts ENIInterface list to JSON for logging
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
func ResolvePatterns(logger *slog.Logger, patterns []string) []string {
	detector := NewInterfaceDetector(logger)
	var resolved []string
	
	for _, pattern := range patterns {
		isAWS, _ := IsAWSPattern(pattern)
		if !isAWS {
			// Not an AWS pattern, keep as-is
			resolved = append(resolved, pattern)
			continue
		}
		
		// Resolve AWS pattern to actual interface names
		awsInterfaces, err := detector.ResolveAWSPattern(pattern)
		if err != nil {
			logger.Warn("Failed to resolve AWS pattern, keeping original",
				"pattern", pattern,
				logfields.Error, err)
			resolved = append(resolved, pattern)
			continue
		}
		
		logger.Info("Resolved AWS pattern",
			"pattern", pattern,
			"interfaces", strings.Join(awsInterfaces, ", "))
		
		resolved = append(resolved, awsInterfaces...)
	}
	
	return resolved
}

