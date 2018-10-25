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
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/cilium/cilium/api/v1/models"
	pkg "github.com/cilium/cilium/pkg/client"

	"github.com/russross/blackfriday"
	"github.com/spf13/cobra"
)

// outputTypes enum definition
type outputType int

// outputTypes enum values
const (
	STDOUT outputType = 0 + iota
	MARKDOWN
	HTML
)

// outputTypes enum strings
var outputTypes = [...]string{
	"STDOUT",
	"MARKDOWN",
	"HTML",
}

var debuginfoCmd = &cobra.Command{
	Use:   "debuginfo",
	Short: "Request available debugging information from agent",
	Run:   runDebugInfo,
}

var (
	file           string
	html           string
	filePerCommand bool
)

type addSection func(*tabwriter.Writer, *models.DebugInfo)

var sections = map[string]addSection{
	"cilium-version":          addCiliumVersion,
	"kernel-version":          addKernelVersion,
	"cilium-status":           addCiliumStatus,
	"cilium-environment-keys": addCiliumEnvironmentKeys,
	"cilium-endpoint-list":    addCiliumEndpointList,
	"cilium-service-list":     addCiliumServiceList,
	"cilium-policy":           addCiliumPolicy,
	"cilium-memory-map":       addCiliumMemoryMap,
}

func init() {
	rootCmd.AddCommand(debuginfoCmd)
	debuginfoCmd.Flags().StringVarP(&file, "file", "f", "", "Redirect output to file")
	debuginfoCmd.Flags().StringVarP(&html, "html-file", "", "", "Convert default output to HTML file")
	debuginfoCmd.Flags().BoolVarP(&filePerCommand, "file-per-command", "", false, "Generate a single file per command")
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

	// define output type and file path
	var output outputType
	var path string

	switch {
	case len(file) > 0: // Markdown file
		output = MARKDOWN
		path = file
	case len(html) > 0: // HTML file
		output = HTML
		path = html
	default: // Write to standard output
		output = STDOUT
	}

	// create tab-writer to fill buffer
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 5, 0, 3, ' ', 0)
	p := resp.Payload

	// generate multiple files
	if (len(file) > 0 || len(html) > 0) && filePerCommand {
		for cmdName, section := range sections {
			addHeader(w)
			section(w, p)
			writeToOutput(buf, output, path, cmdName)
			buf.Reset()
		}
		return
	}

	// generate a single file
	addHeader(w)
	for _, section := range sections {
		section(w, p)
	}
	writeToOutput(buf, output, path, "")

}

func addHeader(w *tabwriter.Writer) {
	fmt.Fprintf(w, "# Cilium debug information\n")
}

func addCiliumVersion(w *tabwriter.Writer, p *models.DebugInfo) {
	printMD(w, "Cilium version", p.CiliumVersion)
}

func addKernelVersion(w *tabwriter.Writer, p *models.DebugInfo) {
	printMD(w, "Kernel version", p.KernelVersion)
}

func addCiliumStatus(w *tabwriter.Writer, p *models.DebugInfo) {
	printMD(w, "Cilium status", "")
	printTicks(w)
	pkg.FormatStatusResponse(w, p.CiliumStatus, true, true, true, true)
	printTicks(w)
}

func addCiliumEnvironmentKeys(w *tabwriter.Writer, p *models.DebugInfo) {
	printMD(w, "Cilium environment keys", strings.Join(p.EnvironmentVariables, "\n"))
}

func addCiliumEndpointList(w *tabwriter.Writer, p *models.DebugInfo) {
	printMD(w, "Endpoint list", "")
	printTicks(w)
	printEndpointList(w, p.EndpointList)
	printTicks(w)

	for _, ep := range p.EndpointList {
		epID := strconv.FormatInt(ep.ID, 10)
		printList(w, "BPF Policy Get "+epID, "bpf", "policy", "get", epID, "-n")
		printList(w, "BPF CT List "+epID, "bpf", "ct", "list", epID)
		printList(w, "Endpoint Get "+epID, "endpoint", "get", epID)
		printList(w, "Endpoint Health "+epID, "endpoint", "health", epID)
		printList(w, "Endpoint Log "+epID, "endpoint", "log", epID)

		if ep.Status != nil && ep.Status.Identity != nil {
			id := strconv.FormatInt(ep.Status.Identity.ID, 10)
			printList(w, "Identity get "+id, "identity", "get", id)
		}
	}
}

func addCiliumServiceList(w *tabwriter.Writer, p *models.DebugInfo) {
	printMD(w, "Service list", "")
	printTicks(w)
	printServiceList(w, p.ServiceList)
	printTicks(w)
}

func addCiliumPolicy(w *tabwriter.Writer, p *models.DebugInfo) {
	printMD(w, "Policy get", fmt.Sprintf(":\n %s\nRevision: %d\n", p.Policy.Policy, p.Policy.Revision))
}

func addCiliumMemoryMap(w *tabwriter.Writer, p *models.DebugInfo) {
	printMD(w, "Cilium memory map\n", p.CiliumMemoryMap)
	if nm := p.CiliumNodemonitorMemoryMap; len(nm) > 0 {
		printMD(w, "Cilium nodemonitor memory map", p.CiliumNodemonitorMemoryMap)
	}
}

func writeToOutput(buf bytes.Buffer, output outputType, path string, suffix string) {
	data := buf.Bytes()
	if output == STDOUT {
		// Write to standard output
		fmt.Println(string(data))
		return
	}

	fileName := fileName(path, suffix)

	switch output {
	case MARKDOWN:
		// Markdown file
		writeMarkdown(data, fileName)
	case HTML:
		// HTML file
		writeHTML(data, fileName)
	}

	fmt.Printf("%s output at %s\n", outputTypes[output], fileName)
}

func fileName(path, suffix string) string {
	if len(suffix) == 0 {
		// no suffix, return path
		return path
	}

	ext := filepath.Ext(path)
	if ext != "" {
		// insert suffix and move extension to back
		return fmt.Sprintf("%s-%s%s", strings.TrimSuffix(path, ext), suffix, ext)
	}
	// no extension, just append suffix
	return fmt.Sprintf("%s-%s", path, suffix)
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
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not create file %s", path)
	}
	w := tabwriter.NewWriter(f, 5, 0, 3, ' ', 0)
	w.Write(data)
}
