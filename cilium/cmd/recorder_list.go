// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/command"
)

// recorderListCmd represents the recorder_list command
var recorderListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List current pcap recorders",
	Run: func(cmd *cobra.Command, args []string) {
		listRecorders(cmd, args)
		listMasks(cmd, args)
	},
}

func init() {
	recorderCmd.AddCommand(recorderListCmd)
	command.AddOutputOption(recorderListCmd)
}

func listMasks(cmd *cobra.Command, args []string) {
	list, err := client.GetRecorderMasks()
	if err != nil {
		Fatalf("Cannot get recorder mask list: %s", err)
	}

	if command.OutputOption() {
		if err := command.PrintOutput(list); err != nil {
			os.Exit(1)
		}
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
	printRecorderMaskList(w, list)
}

func printRecorderMaskList(w *tabwriter.Writer, maskList []*models.RecorderMask) {
	maskList4 := []*models.RecorderMask{}
	maskList6 := []*models.RecorderMask{}
	fmt.Fprintln(w, "Users\tPriority   \tWildcard Masks\t")
	for _, mask := range maskList {
		if mask.Status == nil || mask.Status.Realized == nil {
			fmt.Fprint(os.Stderr, "error parsing recorder: empty state")
			continue
		}
		if len(mask.Status.Realized.SrcPrefixMask) == 8 {
			maskList4 = append(maskList4, mask)
		} else {
			maskList6 = append(maskList6, mask)
		}
	}
	sort.Slice(maskList4, func(i, j int) bool {
		return maskList4[i].Status.Realized.Priority > maskList4[j].Status.Realized.Priority
	})
	sort.Slice(maskList6, func(i, j int) bool {
		return maskList6[i].Status.Realized.Priority > maskList6[j].Status.Realized.Priority
	})
	for _, mask := range maskList6 {
		spec := mask.Status.Realized
		str := fmt.Sprintf("%d\t%d\t%s:%s\t->\t%s:%s\t%s",
			spec.Users, spec.Priority,
			spec.SrcPrefixMask, spec.SrcPortMask,
			spec.DstPrefixMask, spec.DstPortMask,
			spec.ProtocolMask)
		fmt.Fprintln(w, str)
	}
	for _, mask := range maskList4 {
		spec := mask.Status.Realized
		str := fmt.Sprintf("%d\t%d\t%s:%s\t->\t%s:%s\t%s",
			spec.Users, spec.Priority,
			spec.SrcPrefixMask, spec.SrcPortMask,
			spec.DstPrefixMask, spec.DstPortMask,
			spec.ProtocolMask)
		fmt.Fprintln(w, str)
	}
	w.Flush()
}

func listRecorders(cmd *cobra.Command, args []string) {
	list, err := client.GetRecorder()
	if err != nil {
		Fatalf("Cannot get recorder list: %s", err)
	}

	if command.OutputOption() {
		if err := command.PrintOutput(list); err != nil {
			os.Exit(1)
		}
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
	printRecorderList(w, list)
}

func printRecorderList(w *tabwriter.Writer, recList []*models.Recorder) {
	fmt.Fprintln(w, "ID\tCapture Length\tWildcard Filters\t")
	for _, rec := range recList {
		if rec.Status == nil || rec.Status.Realized == nil {
			fmt.Fprint(os.Stderr, "error parsing recorder: empty state")
			continue
		}
	}
	sort.Slice(recList, func(i, j int) bool {
		return *recList[i].Status.Realized.ID <= *recList[j].Status.Realized.ID
	})
	for _, rec := range recList {
		spec := rec.Status.Realized
		capLen := "full"
		if spec.CaptureLength != 0 {
			capLen = fmt.Sprintf("<= %d", spec.CaptureLength)
		}
		if len(spec.Filters) > 0 {
			str := fmt.Sprintf("%d\t%s\t%s:%s\t->\t%s:%s\t%s",
				int64(*spec.ID), capLen,
				spec.Filters[0].SrcPrefix, spec.Filters[0].SrcPort,
				spec.Filters[0].DstPrefix, spec.Filters[0].DstPort,
				spec.Filters[0].Protocol)
			fmt.Fprintln(w, str)
		} else {
			str := fmt.Sprintf("%d\t%s\t(none)", int64(*spec.ID), capLen)
			fmt.Fprintln(w, str)
			continue
		}
		for _, filter := range spec.Filters[1:] {
			str := fmt.Sprintf("\t\t%s:%s\t->\t%s:%s\t%s",
				filter.SrcPrefix, filter.SrcPort,
				filter.DstPrefix, filter.DstPort,
				filter.Protocol)
			fmt.Fprintln(w, str)
		}
	}
	fmt.Fprintln(w, "")
	w.Flush()
}
