// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os/exec"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/prometheus/procfs"
	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/api/v1/client/daemon"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/common/ipsec"
)

const (
	// Cilium uses reqid 1 to tie the IPsec security policies to their matching state
	ciliumReqId = "1"
)

var (
	regex = regexp.MustCompile("oseq[[:blank:]]0[xX]([[:xdigit:]]+)")
)

var encryptStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Display the current encryption state",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium encrypt status")
		status, err := getEncryptionStatus()
		if err != nil {
			Fatalf("Cannot get daemon encryption status: %s", err)
		}
		if command.OutputOption() {
			if err := command.PrintOutput(status); err != nil {
				Fatalf("error getting output in JSON: %s\n", err)
			}
		} else {
			printEncryptionStatus(status)
		}
	},
}

func init() {
	CncryptCmd.AddCommand(encryptStatusCmd)
	command.AddOutputOption(encryptStatusCmd)
}

func getEncryptionStatus() (models.EncryptionStatus, error) {
	params := daemon.NewGetHealthzParamsWithTimeout(timeout)
	params.SetBrief(&brief)
	resp, err := client.Daemon.GetHealthz(params)
	if err != nil {
		return models.EncryptionStatus{}, err
	}

	enc := resp.Payload.Encryption
	switch enc.Mode {
	case models.EncryptionStatusModeIPsec:
		return dumpIPsecStatus()
	case models.EncryptionStatusModeWireguard:
		return dumpWireGuardStatus(enc), nil
	}
	return models.EncryptionStatus{Mode: models.EncryptionStatusModeDisabled}, nil
}

func dumpIPsecStatus() (models.EncryptionStatus, error) {
	status := models.EncryptionStatus{
		Mode:  models.EncryptionStatusModeIPsec,
		Ipsec: &models.IPsecStatus{},
	}
	xfrmStates, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
	if err != nil {
		return models.EncryptionStatus{}, fmt.Errorf("cannot get xfrm state: %s", err)
	}
	keys, err := ipsec.CountUniqueIPsecKeys(xfrmStates)
	if err != nil {
		return models.EncryptionStatus{}, fmt.Errorf("error counting IPsec keys: %s\n", err)
	}
	status.Ipsec.KeysInUse = int64(keys)
	decryptInts, err := getDecryptionInterfaces()
	if err != nil {
		return models.EncryptionStatus{}, fmt.Errorf("error getting IPsec decryption interfaces: %s\n", err)
	}
	status.Ipsec.DecryptInterfaces = decryptInts
	seqNum, err := maxSequenceNumber()
	if err != nil {
		return models.EncryptionStatus{}, fmt.Errorf("error getting IPsec max sequence number: %s\n", err)
	}
	status.Ipsec.MaxSeqNumber = seqNum
	errCount, errMap, err := getXfrmStats("")
	if err != nil {
		return models.EncryptionStatus{}, fmt.Errorf("error getting xfrm stats: %s\n", err)
	}
	status.Ipsec.ErrorCount = errCount
	status.Ipsec.XfrmErrors = errMap
	return status, nil
}

func dumpWireGuardStatus(p *models.EncryptionStatus) models.EncryptionStatus {
	status := models.EncryptionStatus{
		Mode: models.EncryptionStatusModeWireguard,
		Wireguard: &models.WireguardStatus{
			Interfaces: make([]*models.WireguardInterface, 0),
		},
	}
	for _, wg := range p.Wireguard.Interfaces {
		status.Wireguard.Interfaces = append(status.Wireguard.Interfaces, &models.WireguardInterface{
			Name:      wg.Name,
			PublicKey: wg.PublicKey,
			PeerCount: wg.PeerCount,
		})
	}
	return status
}

func getXfrmStats(mountPoint string) (int64, map[string]int64, error) {
	fs, err := procfs.NewDefaultFS()
	if mountPoint != "" {
		fs, err = procfs.NewFS(mountPoint)
	}
	if err != nil {
		return 0, nil, fmt.Errorf("cannot get a new proc FS: %s", err)
	}
	stats, err := fs.NewXfrmStat()
	if err != nil {
		return 0, nil, fmt.Errorf("failed to read xfrm statistics: %s", err)
	}
	v := reflect.ValueOf(stats)
	countErrors := int64(0)
	errorMap := make(map[string]int64)
	if v.Type().Kind() == reflect.Struct {
		for i := 0; i < v.NumField(); i++ {
			name := v.Type().Field(i).Name
			value := v.Field(i).Interface().(int)
			if value != 0 {
				countErrors += int64(value)
				errorMap[name] = int64(value)
			}
		}
	}
	return countErrors, errorMap, nil
}

func extractMaxSequenceNumber(ipOutput string) (int64, error) {
	maxSeqNum := int64(0)
	lines := strings.Split(ipOutput, "\n")
	for _, line := range lines {
		matched := regex.FindStringSubmatchIndex(line)
		if matched != nil {
			oseq, err := strconv.ParseInt(line[matched[2]:matched[3]], 16, 64)
			if err != nil {
				return 0, fmt.Errorf("failed to parse sequence number '%s': %s",
					line[matched[2]:matched[3]], err)
			}
			if oseq > maxSeqNum {
				maxSeqNum = oseq
			}
		}
	}
	return maxSeqNum, nil
}

func maxSequenceNumber() (string, error) {
	out, err := exec.Command("ip", "xfrm", "state", "list", "reqid", ciliumReqId).Output()
	if err != nil {
		return "", fmt.Errorf("cannot get xfrm states: %s", err)
	}
	maxSeqNum, err := extractMaxSequenceNumber(string(out))
	if err != nil {
		return "", err
	}
	if maxSeqNum == 0 {
		return "N/A", nil
	}
	return fmt.Sprintf("0x%x/0xffffffff", maxSeqNum), nil
}

func isDecryptionInterface(link netlink.Link) (bool, error) {
	filters, err := netlink.FilterList(link, tcFilterParentIngress)
	if err != nil {
		return false, err
	}
	for _, f := range filters {
		if bpfFilter, ok := f.(*netlink.BpfFilter); ok {
			// We consider the interface a decryption interface if it has the
			// BPF program we use to mark ESP packets for decryption, that is
			// the cil_from_network BPF program.
			if strings.Contains(bpfFilter.Name, "cil_from_network") {
				return true, nil
			}
		}
	}
	return false, nil
}

func getDecryptionInterfaces() ([]string, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("failed to list interfaces: %s", err)
	}
	decryptionIfaces := []string{}
	for _, link := range links {
		itIs, err := isDecryptionInterface(link)
		if err != nil {
			return nil, fmt.Errorf("failed to list BPF programs for %s: %s", link.Attrs().Name, err)
		}
		if itIs {
			decryptionIfaces = append(decryptionIfaces, link.Attrs().Name)
		}
	}
	return decryptionIfaces, nil
}

func printEncryptionStatus(status models.EncryptionStatus) {
	fmt.Printf("Encryption: %-26s\n", status.Mode)
	switch status.Mode {
	case models.EncryptionStatusModeIPsec:
		fmt.Printf("Decryption interface(s): %s\n", strings.Join(status.Ipsec.DecryptInterfaces, ", "))
		fmt.Printf("Keys in use: %-26d\n", status.Ipsec.KeysInUse)
		fmt.Printf("Max Seq. Number: %s\n", status.Ipsec.MaxSeqNumber)
		fmt.Printf("Errors: %-26d\n", status.Ipsec.ErrorCount)
		for k, v := range status.Ipsec.XfrmErrors {
			fmt.Printf("\t%s: %-26d\n", k, v)
		}
	case models.EncryptionStatusModeWireguard:
		for _, s := range status.Wireguard.Interfaces {
			fmt.Printf("Interface: %s\n", s.Name)
			fmt.Printf("\tPublic key: %s\n", s.PublicKey)
			fmt.Printf("\tNumber of peers: %d\n", s.PeerCount)
		}
	}
}
