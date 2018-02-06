// Copyright 2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"text/tabwriter"

	pkg "github.com/cilium/cilium/pkg/client"

	"github.com/russross/blackfriday"
	"github.com/spf13/cobra"
)

var debuginfoCmd = &cobra.Command{
	Use:   "debuginfo",
	Short: "Request available debugging information from agent",
	Run:   runDebugInfo,
}

var (
	file string
	html string
)

func init() {
	rootCmd.AddCommand(debuginfoCmd)
	debuginfoCmd.Flags().StringVarP(&file, "file", "f", "", "Redirect output to file")
	debuginfoCmd.Flags().StringVarP(&html, "html-file", "", "", "Convert default output to HTML file")
}

func runDebugInfo(cmd *cobra.Command, args []string) {
	if os.Getuid() != 0 {
		fmt.Fprint(os.Stderr, "Warning, some of the BPF commands might fail when run as not root\n")
	}

	resp, err := client.Daemon.GetDebuginfo(nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", pkg.Hint(err))
		os.Exit(1)
	}

	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 5, 0, 3, ' ', 0)
	p := resp.Payload
	fmt.Fprintf(w, "# Cilium debug information\n")

	printMD(w, "Cilium version", p.CiliumVersion)
	printMD(w, "Kernel version", p.KernelVersion)

	printMD(w, "Cilium status", "")
	printTicks(w)
	pkg.FormatStatusResponse(w, p.CiliumStatus, true)
	printTicks(w)

	printMD(w, "Cilium environment keys", strings.Join(p.EnvironmentVariables, "\n"))

	printMD(w, "Endpoint list", "")
	printTicks(w)
	printEndpointList(w, p.EndpointList)
	printTicks(w)

	for _, ep := range p.EndpointList {
		epID := strconv.FormatInt(ep.ID, 10)
		printList(w, "BPF Endpoint List "+epID, "bpf", "endpoint", "list", epID)
		printList(w, "BPF Policy List "+epID, "bpf", "policy", "list", epID)
		printList(w, "BPF CT List "+epID, "bpf", "ct", "list", epID)
		printList(w, "BPF LB List "+epID, "bpf", "lb", "list", epID)
		printList(w, "BPF Tunnel List "+epID, "bpf", "tunnel", "list", epID)
		printList(w, "Endpoint Get "+epID, "endpoint", "get", epID)

		if ep.Identity != nil {
			id := strconv.FormatInt(ep.Identity.ID, 10)
			printList(w, "Identity get "+id, "identity", "get", id)
		}
	}

	printMD(w, "Service list", "")
	printTicks(w)
	printServiceList(w, p.ServiceList)
	printTicks(w)

	printMD(w, "Policy get", fmt.Sprintf(":\n %s\nRevision: %d\n", p.Policy.Policy, p.Policy.Revision))
	printMD(w, "Cilium memory map\n", p.CiliumMemoryMap)
	if nm := p.CiliumNodemonitorMemoryMap; len(nm) > 0 {
		printMD(w, "Cilium nodemonitor memory map", p.CiliumNodemonitorMemoryMap)
	}

	data := buf.Bytes()
	switch {
	case len(file) > 0: // Markdown file
		writeMarkdown(data, file)
		fmt.Printf("Markdown output at %s\n", file)
	case len(html) > 0: // HTML file
		writeHTML(data, html)
		fmt.Printf("HTML output at %s\n", html)
	default: // Write to standard output
		fmt.Println(string(data))
	}
}

func printList(w io.Writer, header string, args ...string) {
	output, _ := exec.Command("cilium", args...).CombinedOutput()
	printMD(w, header, string(output))
}

func printMD(w io.Writer, header string, body string) {
	if len(body) > 0 {
		fmt.Fprintf(w, "\n#### %s\n\n```\n%s\n```\n\n", header, body)
	} else {
		fmt.Fprintf(w, "\n#### %s\n\n", header)
	}
}

func printTicks(w io.Writer) {
	fmt.Fprint(w, "```\n")
}

func writeHTML(data []byte, path string) {
	output := blackfriday.MarkdownCommon(data)
	if err := ioutil.WriteFile(path, output, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error while writing HTML file %s", err)
		return
	}
}

func writeMarkdown(data []byte, path string) {
	f, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not create file %s", file)
	}
	w := tabwriter.NewWriter(f, 5, 0, 3, ' ', 0)
	w.Write(data)
}
