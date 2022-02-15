// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/russross/blackfriday/v2"
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/api/v1/models"
	pkg "github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/command"
)

// outputTypes enum definition
type outputType int

// outputTypes enum values
const (
	STDOUT outputType = 0 + iota
	MARKDOWN
	HTML
	JSONOUTPUT
	JSONPATH
)

const (
	// Can't call it jsonOutput because another var in this package uses that.
	jsonOutputDebuginfo = "json"
	markdownOutput      = "markdown"
	htmlOutput          = "html"
	jsonpathOutput      = "jsonpath"
)

var (
	jsonPathRegExp = regexp.MustCompile(`^jsonpath\=(.*)`)
)

// outputTypes enum strings
var outputTypes = [...]string{
	"STDOUT",
	markdownOutput,
	htmlOutput,
	jsonOutputDebuginfo,
	jsonpathOutput,
}

var debuginfoCmd = &cobra.Command{
	Use:   "debuginfo",
	Short: "Request available debugging information from agent",
	Run:   runDebugInfo,
}

var (
	outputToFile   bool
	filePerCommand bool
	outputOpts     []string
	outputDir      string
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
	"cilium-subsystems":       addSubsystems,
	"cilium-encryption":       addEncryption,
}

func init() {
	rootCmd.AddCommand(debuginfoCmd)
	debuginfoCmd.Flags().BoolVarP(&outputToFile, "file", "f", false, "Redirect output to file(s)")
	debuginfoCmd.Flags().BoolVarP(&filePerCommand, "file-per-command", "", false, "Generate a single file per command")
	debuginfoCmd.Flags().StringSliceVar(&outputOpts, "output", []string{}, "markdown| html| json| jsonpath='{}'")
	debuginfoCmd.Flags().StringVar(&outputDir, "output-directory", "", "directory for files (if specified will use directory in which this command was ran)")
}

func validateInput() []outputType {
	if outputDir != "" && !outputToFile {
		fmt.Fprintf(os.Stderr, "invalid option combination; specified output-directory %q, but did not specify for output to be redirected to file; exiting\n", outputDir)
		os.Exit(1)
	}
	return validateOutputOpts()
}

func validateOutputOpts() []outputType {
	var outputTypes []outputType
	for _, outputOpt := range outputOpts {
		switch strings.ToLower(outputOpt) {
		case markdownOutput:
			outputTypes = append(outputTypes, MARKDOWN)
		case htmlOutput:
			if !outputToFile {
				fmt.Fprintf(os.Stderr, "if HTML is specified as the output format, it is required that you provide the `--file` argument as well\n")
				os.Exit(1)
			}
			outputTypes = append(outputTypes, HTML)
		case jsonOutputDebuginfo:
			if filePerCommand {
				fmt.Fprintf(os.Stderr, "%s does not support dumping a file per command; exiting\n", outputOpt)
				os.Exit(1)
			}
			outputTypes = append(outputTypes, JSONOUTPUT)
		// Empty JSONPath filter case.
		case jsonpathOutput:
			if filePerCommand {
				fmt.Fprintf(os.Stderr, "%s does not support dumping a file per command; exiting\n", outputOpt)
				os.Exit(1)
			}
			outputTypes = append(outputTypes, JSONPATH)
		default:
			// Check to see if arg contains jsonpath filtering as well.
			if jsonPathRegExp.MatchString(outputOpt) {
				outputTypes = append(outputTypes, JSONPATH)
				continue
			}
			fmt.Fprintf(os.Stderr, "%s is not a valid output format; exiting\n", outputOpt)
			os.Exit(1)
		}
	}
	return outputTypes
}

func formatFileName(outputDir string, cmdTime time.Time, outtype outputType) string {
	var fileName string
	var sep string
	if outputDir != "" {
		sep = outputDir + "/"
	}
	timeStr := cmdTime.Format("20060102-150405.999-0700-MST")
	switch outtype {
	case MARKDOWN:
		fileName = fmt.Sprintf("%scilium-debuginfo-%s.md", sep, timeStr)
	case HTML:
		fileName = fmt.Sprintf("%scilium-debuginfo-%s.html", sep, timeStr)
	case JSONOUTPUT:
		fileName = fmt.Sprintf("%scilium-debuginfo-%s.json", sep, timeStr)
	case JSONPATH:
		fileName = fmt.Sprintf("%scilium-debuginfo-%s.jsonpath", sep, timeStr)
	default:
		fileName = fmt.Sprintf("%scilium-debuginfo-%s.md", sep, timeStr)
	}
	return fileName
}

func rootWarningMessage() {
	fmt.Fprint(os.Stderr, "Warning, some of the BPF commands might fail when not run as root\n")
}

func runDebugInfo(cmd *cobra.Command, args []string) {
	outputTypes := validateInput()

	resp, err := client.Daemon.GetDebuginfo(nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", pkg.Hint(err))
		os.Exit(1)
	}

	// create tab-writer to fill buffer
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 5, 0, 3, ' ', 0)
	p := resp.Payload

	cmdTime := time.Now()

	if outputToFile && len(outputTypes) == 0 {
		outputTypes = append(outputTypes, MARKDOWN)
	}

	// Dump payload for each output format.
	for i, output := range outputTypes {
		var fileName string

		// Only warn when not dumping output as JSON so that when the output of the
		// command is specified to be JSON, the only outputted content is the JSON
		// model of debuginfo.
		if os.Getuid() != 0 && output != JSONOUTPUT && output != JSONPATH {
			rootWarningMessage()
		}

		if outputToFile {
			fileName = formatFileName(outputDir, cmdTime, output)
		}

		// Generate multiple files for each subsection of the command if
		// specified, except in the JSON cases, because in the JSON cases,
		// we want to dump the entire DebugInfo JSON object, not sections of it.
		if filePerCommand && (output != JSONOUTPUT && output != JSONPATH) {
			for cmdName, section := range sections {
				addHeader(w)
				section(w, p)
				writeToOutput(buf, output, fileName, cmdName)
				buf.Reset()
			}
			continue
		}

		// Generate a single file, except not for JSON; no formatting is
		// needed.
		if output == JSONOUTPUT || output == JSONPATH {
			marshaledDebugInfo, _ := p.MarshalBinary()
			buf.Write(marshaledDebugInfo)
			if output == JSONOUTPUT {
				writeToOutput(buf, output, fileName, "")
			} else {
				writeJSONPathToOutput(buf, fileName, "", outputOpts[i])
			}
			buf.Reset()
		} else {
			addHeader(w)
			for _, section := range sections {
				section(w, p)
			}
			writeToOutput(buf, output, fileName, "")
			buf.Reset()
		}
	}

	if len(outputTypes) > 0 {
		return
	}

	if os.Getuid() != 0 {
		rootWarningMessage()
	}

	// Just write to stdout in markdown formats if no output option specified.
	addHeader(w)
	for _, section := range sections {
		section(w, p)
	}
	writeToOutput(buf, STDOUT, "", "")
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
	pkg.FormatStatusResponse(w, p.CiliumStatus, pkg.StatusAllDetails)
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

func addSubsystems(w *tabwriter.Writer, p *models.DebugInfo) {
	for name, status := range p.Subsystem {
		printMD(w, name, status)
	}
}

func addCiliumMemoryMap(w *tabwriter.Writer, p *models.DebugInfo) {
	printMD(w, "Cilium memory map\n", p.CiliumMemoryMap)
	if nm := p.CiliumNodemonitorMemoryMap; len(nm) > 0 {
		printMD(w, "Cilium nodemonitor memory map", p.CiliumNodemonitorMemoryMap)
	}
}

func addEncryption(w *tabwriter.Writer, p *models.DebugInfo) {
	printMD(w, "Cilium encryption\n", "")

	if p.Encryption != nil && p.Encryption.Wireguard != nil {
		fmt.Fprint(w, "##### Wireguard\n\n")
		printTicks(w)
		for _, wg := range p.Encryption.Wireguard.Interfaces {
			fmt.Fprintf(w, "interface: %s\n", wg.Name)
			fmt.Fprintf(w, "  public key: %s\n", wg.PublicKey)
			fmt.Fprintf(w, "  listening port: %d\n", wg.ListenPort)
			for _, peer := range wg.Peers {
				fmt.Fprintf(w, "\npeer: %s\n", peer.PublicKey)
				fmt.Fprintf(w, "  endpoint: %s\n", peer.Endpoint)
				fmt.Fprintf(w, "  allowed ips: %s\n", strings.Join(peer.AllowedIps, ", "))
				fmt.Fprintf(w, "  latest handshake: %s\n", peer.LastHandshakeTime)
				fmt.Fprintf(w, "  transfer: %d B received, %d B sent\n", peer.TransferRx, peer.TransferTx)
			}
			fmt.Fprint(w, "\n")
		}
		printTicks(w)
	}

}

func writeJSONPathToOutput(buf bytes.Buffer, path string, suffix string, jsonPath string) {
	data := buf.Bytes()
	db := &models.DebugInfo{}
	err := db.UnmarshalBinary(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error unmarshaling binary: %s\n", err)
	}
	jsonStr, err := command.DumpJSONToString(db, jsonPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error printing JSON: %s\n", err)
	}

	if path == "" {
		fmt.Println(jsonStr)
		return
	}

	fileName := fileName(path, suffix)
	writeFile([]byte(jsonStr), fileName)

	fmt.Printf("%s output at %s\n", jsonpathOutput, fileName)
	return
}

func writeToOutput(buf bytes.Buffer, output outputType, path string, suffix string) {
	data := buf.Bytes()

	if path == "" {
		switch output {
		case JSONOUTPUT:
			db := &models.DebugInfo{}
			err := db.UnmarshalBinary(data)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error unmarshaling binary: %s\n", err)
			}

			err = command.PrintOutputWithType(db, "json")
			if err != nil {
				fmt.Fprintf(os.Stderr, "error printing JSON: %s\n", err)
			}
		default:
			fmt.Println(string(data))
		}
		return
	}

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
	case JSONOUTPUT:
		writeJSON(data, fileName)
	case JSONPATH:
		writeJSON(data, fileName)
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
	output := blackfriday.Run(data)
	if err := os.WriteFile(path, output, 0644); err != nil {
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

func writeFile(data []byte, path string) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not create file %s", path)
		os.Exit(1)
	}
	f.Write(data)
}

func writeJSON(data []byte, path string) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not create file %s", path)
		os.Exit(1)
	}

	db := &models.DebugInfo{}

	// Unmarshal the binary so we can indent the JSON appropriately when we
	// display it to end-users.
	err = db.UnmarshalBinary(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error unmarshaling binary: %s\n", err)
		os.Exit(1)
	}
	result, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error marshal-indenting data: %s\n", err)
		os.Exit(1)
	}
	f.Write(result)
}
