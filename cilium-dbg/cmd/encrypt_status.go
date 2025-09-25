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
	"golang.zx2c4.com/wireguard/wgctrl"

	"github.com/cilium/cilium/api/v1/client/daemon"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/common/ipsec"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
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
			Fatalf("Cannot get encryption status: %s", err)
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
	EncryptCmd.AddCommand(encryptStatusCmd)
	command.AddOutputOption(encryptStatusCmd)
}

func getEncryptionStatus() (models.EncryptionStatus, error) {
	var result models.EncryptionStatus

	params := daemon.NewGetHealthzParamsWithTimeout(timeout)
	params.SetBrief(&brief)

	resp, err := client.Daemon.GetHealthz(params)
	if err != nil {
		result.Msg = err.Error()
	} else {
		result.Mode = resp.Payload.Encryption.Mode
	}

	result.Ipsec, err = dumpIPsecStatus()
	if err != nil {
		return result, err
	}

	result.Wireguard, err = dumpWireGuardStatus()
	if err != nil {
		return result, err
	}

	return result, nil
}

// filterReqID returns the subset of the `xfrmStates` that match the `reqID` passed in.
func filterReqID(reqID int, xfrmStates []netlink.XfrmState) []netlink.XfrmState {
	var result []netlink.XfrmState
	for _, s := range xfrmStates {
		if s.Reqid != reqID {
			continue
		}

		result = append(result, s)
	}

	return result
}

func dumpIPsecStatus() (*models.IPsecStatus, error) {
	xfrmStates, err := safenetlink.XfrmStateList(netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("cannot get xfrm state: %w", err)
	}

	xfrmStates = filterReqID(ipsec.DefaultReqID, xfrmStates)

	keys, err := ipsec.CountUniqueIPsecKeys(xfrmStates)
	if err != nil {
		return nil, fmt.Errorf("error counting IPsec keys: %w", err)
	}

	// no ipsec state installed
	if keys == 0 {
		return nil, nil
	}

	var result models.IPsecStatus

	result.KeysInUse = int64(keys)

	result.DecryptInterfaces, err = getDecryptionInterfaces()
	if err != nil {
		return nil, fmt.Errorf("error getting IPsec decryption interfaces: %w", err)
	}

	result.MaxSeqNumber, err = maxSequenceNumber()
	if err != nil {
		return nil, fmt.Errorf("error getting IPsec max sequence number: %w", err)
	}

	errCount, errMap, err := getXfrmStats("")
	if err != nil {
		return nil, fmt.Errorf("error getting xfrm stats: %w", err)
	}

	result.ErrorCount = errCount
	result.XfrmErrors = errMap
	return &result, nil
}

func dumpWireGuardStatus() (*models.WireguardStatus, error) {
	wgClient, err := wgctrl.New()
	if err != nil {
		return nil, err
	}

	defer wgClient.Close()

	devices, err := wgClient.Devices()
	if err != nil {
		return nil, err
	}

	var result models.WireguardStatus

	for _, d := range devices {
		if d.Name != wgTypes.IfaceName {
			continue
		}

		result.Interfaces = append(result.Interfaces, &models.WireguardInterface{
			Name:      d.Name,
			PublicKey: d.PublicKey.String(),
			PeerCount: int64(len(d.Peers)),
		})
	}

	return &result, nil
}

func getXfrmStats(mountPoint string) (int64, map[string]int64, error) {
	fs, err := procfs.NewDefaultFS()
	if mountPoint != "" {
		fs, err = procfs.NewFS(mountPoint)
	}
	if err != nil {
		return 0, nil, fmt.Errorf("cannot get a new proc FS: %w", err)
	}
	stats, err := fs.NewXfrmStat()
	if err != nil {
		return 0, nil, fmt.Errorf("failed to read xfrm statistics: %w", err)
	}
	v := reflect.ValueOf(stats)
	countErrors := int64(0)
	errorMap := make(map[string]int64)
	if v.Type().Kind() == reflect.Struct {
		for i := range v.NumField() {
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
	for line := range strings.SplitSeq(ipOutput, "\n") {
		matched := regex.FindStringSubmatchIndex(line)
		if matched != nil {
			oseq, err := strconv.ParseInt(line[matched[2]:matched[3]], 16, 64)
			if err != nil {
				return 0, fmt.Errorf("failed to parse sequence number '%s': %w",
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
		return "", fmt.Errorf("cannot get xfrm states: %w", err)
	}
	maxSeqNum, err := extractMaxSequenceNumber(string(out))
	if err != nil {
		return "", err
	}
	if maxSeqNum == 0 {
		return "N/A", nil
	}
	return fmt.Sprintf("0x%x/0xffffffffffffffff", maxSeqNum), nil
}

// isDecryptionInterface returns whether we thing an interface is used for decryption or not.
// FIXME: this simply checks for the existence of the cil_from_network or cil_from_netdev programs
// in the filter list of the interface - ideally there should be a less ambiguous way of knowing if
// an interface is used for decryption such as evaluating the addresses in the xfrm states.
func isDecryptionInterface(link netlink.Link) (bool, error) {
	filters, err := safenetlink.FilterList(link, tcFilterParentIngress)
	if err != nil {
		return false, err
	}
	for _, f := range filters {
		if bpfFilter, ok := f.(*netlink.BpfFilter); ok {
			// We consider the interface a decryption interface if it has the
			// BPF program we use to mark ESP packets for decryption, that is
			// the cil_from_network or cil_from_netdev BPF programs.
			if strings.Contains(bpfFilter.Name, "cil_from_network") ||
				strings.Contains(bpfFilter.Name, "cil_from_netdev") {
				return true, nil
			}
		}
	}
	return false, nil
}

// getDecryptionInterfaces returns the interfaces used for decryption.
func getDecryptionInterfaces() ([]string, error) {
	links, err := safenetlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("failed to list interfaces: %w", err)
	}
	decryptionIfaces := []string{}
	for _, link := range links {
		itIs, err := isDecryptionInterface(link)
		if err != nil {
			return nil, fmt.Errorf("failed to list BPF programs for %s: %w", link.Attrs().Name, err)
		}
		if itIs {
			decryptionIfaces = append(decryptionIfaces, link.Attrs().Name)
		}
	}
	return decryptionIfaces, nil
}

func printEncryptionStatus(status models.EncryptionStatus) {
	if status.Msg != "" {
		fmt.Printf("Msg: %s\n", status.Msg)
	}

	fmt.Printf("Encryption: %-26s\n", status.Mode)
	if status.Ipsec != nil {
		fmt.Printf("Decryption interface(s): %s\n", strings.Join(status.Ipsec.DecryptInterfaces, ", "))
		fmt.Printf("Keys in use: %-26d\n", status.Ipsec.KeysInUse)
		fmt.Printf("Max Seq. Number: %s\n", status.Ipsec.MaxSeqNumber)
		fmt.Printf("Errors: %-26d\n", status.Ipsec.ErrorCount)
		for k, v := range status.Ipsec.XfrmErrors {
			fmt.Printf("\t%s: %-26d\n", k, v)
		}
	}
	if status.Wireguard != nil {
		for _, s := range status.Wireguard.Interfaces {
			fmt.Printf("Interface: %s\n", s.Name)
			fmt.Printf("\tPublic key: %s\n", s.PublicKey)
			fmt.Printf("\tNumber of peers: %d\n", s.PeerCount)
		}
	}
}
