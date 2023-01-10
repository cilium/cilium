// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/api/v1/models"
)

var (
	idRec   uint64
	capLen  uint64
	filters []string
)

// recorderUpdateCmd represents the recorder_update command
var recorderUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update individual pcap recorder",
	Run: func(cmd *cobra.Command, args []string) {
		updateRecorder(cmd, args)
	},
}

func init() {
	recorderCmd.AddCommand(recorderUpdateCmd)
	recorderUpdateCmd.Flags().Uint64VarP(&idRec, "id", "", 0, "Identifier")
	recorderUpdateCmd.Flags().Uint64VarP(&capLen, "caplen", "", 0, "Capture Length (0 is full capture)")
	recorderUpdateCmd.Flags().StringSliceVarP(&filters, "filters", "", []string{}, "List of filters ('<srcCIDR> <srcPort> <dstCIDR> <dstPort> <proto>')")
}

func updateRecorder(cmd *cobra.Command, args []string) {
	var spec *models.RecorderSpec

	id := int64(idRec)
	if id == 0 {
		Usagef(cmd, "Empty recorder id argument")
	}

	rec, err := client.GetRecorderID(id)
	switch {
	case err == nil && (rec.Status == nil || rec.Status.Realized == nil):
		Fatalf("Cannot update recorder %d: empty state", id)
	case err == nil:
		spec = rec.Status.Realized
		fmt.Printf("Updating existing recorder with id '%v'\n", id)
	default:
		spec = &models.RecorderSpec{ID: &id}
		fmt.Printf("Creating new recorder with id '%v'\n", id)
	}

	spec.CaptureLength = int64(capLen)
	spec.Filters = []*models.RecorderFilter{}
	for _, filter := range filters {
		var dstPrefix, srcPrefix, dstPort, srcPort, protocol string
		_, err := fmt.Sscanf(filter, "%s %s %s %s %s",
			&srcPrefix, &srcPort, &dstPrefix, &dstPort, &protocol)
		if err != nil {
			Fatalf("Cannot parse filter: %s", err)
		}
		protocol = strings.ToUpper(protocol)
		switch protocol {
		case models.RecorderFilterProtocolTCP,
			models.RecorderFilterProtocolUDP,
			models.RecorderFilterProtocolANY:
		default:
			Fatalf("Cannot parse filter: %s", err)
		}
		f := &models.RecorderFilter{
			DstPrefix: dstPrefix,
			SrcPrefix: srcPrefix,
			DstPort:   dstPort,
			SrcPort:   srcPort,
			Protocol:  protocol,
		}
		spec.Filters = append(spec.Filters, f)
	}

	if created, err := client.PutRecorderID(id, spec); err != nil {
		Fatalf("Cannot add/update recorder: %s", err)
	} else if created {
		fmt.Printf("Added recorder with %d filter\n", len(spec.Filters))
	} else {
		fmt.Printf("Updated recorder with %d filter\n", len(spec.Filters))
	}
}
