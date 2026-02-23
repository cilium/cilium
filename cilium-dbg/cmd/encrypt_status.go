// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/prometheus/procfs"
	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"

	"github.com/cilium/ebpf"
	ebpf_link "github.com/cilium/ebpf/link"
	"golang.zx2c4.com/wireguard/wgctrl"

	"github.com/cilium/cilium/api/v1/client/daemon"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/common/ipsec"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/types"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

const (
	// Cilium uses reqid 1 to tie the IPsec security policies to their matching state
	ciliumReqId = "1"
)

var (
	regex = regexp.MustCompile("oseq[[:blank:]]0[xX]([[:xdigit:]]+)")

	errWireguardStateMismatch = errors.New("wireguard state mismatch between kernel and agent")
)

var encryptStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Display the current encryption state",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium encrypt status")

		status := getEncryptionStatus()

		if command.OutputOption() {
			if err := command.PrintOutput(status); err != nil {
				Fatalf("error getting output in JSON: %s\n", err)
			}
		} else {
			printEncryptionStatus(status)
		}
	},
}

var encryptDumpXfrmCmd = &cobra.Command{
	Use:   "dump-xfrm",
	Short: "Dump structured XFRM states for test facilitation (internal use only)",
	Long: `Dump structured XFRM states for test facilitation.

This command extracts XFRM state information and outputs it in JSON format
for use by integration tests. Only Cilium-managed states (ReqID == 1) are
included in the output.`,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium encrypt dump-xfrm")
		states, err := dumpXfrmStates()
		if err != nil {
			Fatalf("Cannot dump XFRM states: %s", err)
		}

		output, err := json.Marshal(states)
		if err != nil {
			Fatalf("Cannot marshal XFRM states to JSON: %s", err)
		}

		fmt.Println(string(output))
	},
}

func init() {
	EncryptCmd.AddCommand(encryptStatusCmd)
	EncryptCmd.AddCommand(encryptDumpXfrmCmd)
	command.AddOutputOption(encryptStatusCmd)
}

// validateWireguardState compares two models.WireguardStatus struct and returns
// an error if they do not match.
func validateWireguardStates(agent, kernel *models.WireguardStatus) error {
	switch {
	case agent == nil && kernel == nil:
		return fmt.Errorf("%w: both agent and kernel states are empty", errWireguardStateMismatch)
	case agent == nil && kernel != nil:
		return fmt.Errorf("%w: agent state is empty", errWireguardStateMismatch)
	case agent != nil && kernel == nil:
		return fmt.Errorf("%w: kernel state is empty", errWireguardStateMismatch)
	}

	var errs error
	seenIfaces := make(map[string]struct{})

	findIface := func(ifaces []*models.WireguardInterface, name string) *models.WireguardInterface {
		for _, iface := range ifaces {
			if iface.Name == name {
				return iface
			}
		}
		return nil
	}

	compareIfaces := func(from, to []*models.WireguardInterface, fromLabel, toLabel string) {
		for _, f := range from {
			if _, seen := seenIfaces[f.Name]; seen {
				continue
			}
			seenIfaces[f.Name] = struct{}{}

			t := findIface(to, f.Name)
			if t == nil {
				errs = errors.Join(errs, fmt.Errorf("interface %q exists in %s but is missing in %s",
					f.Name, fromLabel, toLabel))
				continue
			}

			if f.PeerCount != t.PeerCount {
				errs = errors.Join(errs, fmt.Errorf("interface %q: peer count mismatch (%s=%d, %s=%d)",
					f.Name, fromLabel, f.PeerCount, toLabel, t.PeerCount))
			}
			if f.ListenPort != t.ListenPort {
				errs = errors.Join(errs, fmt.Errorf("interface %q: listen port mismatch (%s=%d, %s=%d)",
					f.Name, fromLabel, f.ListenPort, toLabel, t.ListenPort))
			}
			if f.PublicKey != t.PublicKey {
				errs = errors.Join(errs, fmt.Errorf("interface %q: public key mismatch (%s=%s, %s=%s)",
					f.Name, fromLabel, f.PublicKey, toLabel, t.PublicKey))
			}
		}
	}

	if len(agent.Interfaces) != len(kernel.Interfaces) {
		errs = errors.Join(errs, fmt.Errorf("interface count mismatch (agent=%d, kernel=%d)",
			len(agent.Interfaces), len(kernel.Interfaces)))
	}

	compareIfaces(agent.Interfaces, kernel.Interfaces, "agent", "kernel")
	compareIfaces(kernel.Interfaces, agent.Interfaces, "kernel", "agent")

	return errs
}

func getEncryptionStatus() models.EncryptionStatus {
	var status models.EncryptionStatus
	var errs, err error

	// retrieve IPSec state (if any) from kernel anyway.
	status.Ipsec, err = dumpIPsecStatus()
	if err != nil {
		errs = errors.Join(errs, err)
	}
	// retrieve WireGuard state (if any) from kernel anyway.
	status.Wireguard, err = dumpWireGuardStatus()
	if err != nil {
		errs = errors.Join(errs, err)
	}

	// retrieve encryption state from agent.
	params := daemon.NewGetHealthzParamsWithTimeout(timeout)
	params.SetBrief(&brief)

	resp, err := client.Daemon.GetHealthz(params)
	if err != nil {
		errs = errors.Join(errs, err)
	} else {
		// the agent replied, let's set the encryption mode
		status.Mode = resp.Payload.Encryption.Mode
		// in WireGuard mode, the agent replies with the list of interfaces and peers,
		// we can use that to validate the state against what we see in the kernel.
		// this is a nop in case of IPSec or no encryption mode.
		switch status.Mode {
		case models.EncryptionStatusModeWireguard:
			err := validateWireguardStates(status.Wireguard, resp.Payload.Encryption.Wireguard)
			if err != nil {
				errs = errors.Join(errs, err)
			}
		case models.EncryptionStatusModeDisabled, models.EncryptionStatusModeIPsec, models.EncryptionStatusModeZtunnel:
		default:
		}
	}

	if errs != nil {
		status.Msg = errs.Error()
	}

	return status
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

	wgDevice, err := wgClient.Device(wgTypes.IfaceName)
	if err != nil {
		// if we fail here, we probably dont have an interface, so just bail out
		return nil, nil
	}

	var result models.WireguardStatus

	result.Interfaces = append(result.Interfaces, &models.WireguardInterface{
		Name:       wgDevice.Name,
		ListenPort: int64(wgDevice.ListenPort),
		PublicKey:  wgDevice.PublicKey.String(),
		PeerCount:  int64(len(wgDevice.Peers)),
	})

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

// isDecryptionInterface returns whether we think an interface is used for decryption or not.
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

	progs, err := ebpf_link.QueryPrograms(
		ebpf_link.QueryOptions{
			Target: link.Attrs().Index,
			Attach: ebpf.AttachTCXIngress,
		},
	)
	if err != nil {
		// probably not supported
		return false, nil
	}

	for _, p := range progs.Programs {
		prog, err := ebpf.NewProgramFromID(p.ID)
		if err != nil {
			return false, fmt.Errorf("failed to find program: %w for %d", err, p.ID)
		}

		if progInfo, err := prog.Info(); err == nil {
			if strings.Contains(progInfo.Name, "cil_from_network") ||
				strings.Contains(progInfo.Name, "cil_from_netdev") {
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

// dumpXfrmStates extracts XFRM state information using netlink
func dumpXfrmStates() ([]types.XfrmStateInfo, error) {
	states, err := safenetlink.XfrmStateList(netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("failed to list XFRM states: %w", err)
	}

	var ciliumStates []types.XfrmStateInfo
	for _, state := range states {
		// Only include Cilium-managed states (ReqID == 1)
		if state.Reqid == 1 {
			stateInfo := types.XfrmStateInfo{
				Encrypt: ipsec.IsDecryptState(state),
				Src:     state.Src.String(),
				Dst:     state.Dst.String(),
				SPI:     uint32(state.Spi),
				ReqID:   uint32(state.Reqid),
			}

			// Extract algorithm and key information
			if state.Auth != nil {
				stateInfo.AuthAlg = state.Auth.Name
				if len(state.Auth.Key) > 0 {
					stateInfo.AuthKey = fmt.Sprintf("%x", state.Auth.Key)
				}
			}
			if state.Crypt != nil {
				stateInfo.CryptAlg = state.Crypt.Name
				if len(state.Crypt.Key) > 0 {
					stateInfo.CryptKey = fmt.Sprintf("%x", state.Crypt.Key)
				}
			}
			if state.Aead != nil {
				stateInfo.AeadAlg = state.Aead.Name
				if len(state.Aead.Key) > 0 {
					stateInfo.AeadKey = fmt.Sprintf("%x", state.Aead.Key)
				}
			}

			ciliumStates = append(ciliumStates, stateInfo)
		}
	}

	return ciliumStates, nil
}
