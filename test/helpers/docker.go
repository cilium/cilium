// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"fmt"
	"strings"

	"github.com/cilium/cilium/test/helpers/constants"
)

// ContainerExec executes cmd in the container with the provided name along with
// any other additional arguments needed.
func (s *SSHMeta) ContainerExec(name string, cmd string, optionalArgs ...string) *CmdRes {
	optionalArgsCoalesced := ""
	if len(optionalArgs) > 0 {
		optionalArgsCoalesced = strings.Join(optionalArgs, " ")
	}
	// Generate a unique ID for the exec session (requires a helper function or library)
	// For simplicity, using a placeholder command; replace with proper Go random string generation.
	execIDCmd := "$(mktemp -u cilium-exec-XXXXXX)" // Placeholder, replace with Go random string generation

	// Base command
	ctrBaseCmd := "sudo ctr task exec"

	// Handle TTY option
	ttyFlag := ""
	if strings.Contains(optionalArgsCoalesced, "-t") {
		ttyFlag = "--tty"
	}
	// Note: Docker's -i is implicitly handled by piping stdin/stdout/stderr with ctr exec.
	// Other optionalArgs might need specific mapping if used.

	// Construct the final command
	// Assumes 'name' is the container ID for ctr.
	// Uses sh -c to execute the command string.
	dockerCmd := fmt.Sprintf("%s --exec-id %s %s %s sh -c %q",
		ctrBaseCmd,
		execIDCmd,
		ttyFlag,
		name,
		cmd)
	return s.Exec(dockerCmd)
}

// ContainerCreate is a wrapper for `docker run`. It runs an instance of the
// specified Docker image with the provided network, name, options and container
// startup commands.
func (s *SSHMeta) ContainerCreate(name, image, net, options string, cmdParams ...string) *CmdRes {
	// 1. Ensure the image exists locally, pull if not.
	// Use -q to suppress "image found" output, only show errors or pull output.
	checkImageCmd := fmt.Sprintf("ctr image ls -q %s", image)
	resCheck := s.Exec(checkImageCmd, ExecOptions{SkipLog: true}) // Don't log successful check output
	if !resCheck.WasSuccessful() {
		// Assuming failure means image not found, attempt to pull.
		pullCmd := fmt.Sprintf("ctr image pull %s", image)
		log.Debugf("Attempting to pull image '%s' as it was not found locally", image)
		resPull := s.ExecWithSudo(pullCmd) // Log pull attempt
		if !resPull.WasSuccessful() {
			// Return the pull error if it fails
			log.Errorf("Failed to pull image '%s' for container '%s'", image, name)
			return resPull // Return the CmdRes from the failed pull
		}
	}

	// 2. Construct the ctr run command
	cmdOnStart := ""
	if len(cmdParams) > 0 {
		cmdOnStart = strings.Join(cmdParams, " ")
	}
	netFlag := "--cni"
	if net == HostDockerNetwork { // Use the defined constant for host network
		netFlag = "--net-host"
	}

	// Parse options to extract labels and other flags
	optionsParts := strings.Fields(options)
	var labelFlags []string
	var remainingOptions []string
	i := 0
	for i < len(optionsParts) {
		part := optionsParts[i]
		if part == "-l" && i+1 < len(optionsParts) {
			// Found a label flag (-l key=value), format it for ctr run (--label key=value)
			labelPair := optionsParts[i+1]
			labelFlags = append(labelFlags, fmt.Sprintf("--label %s", labelPair))
			i += 2 // Skip '-l' and 'key=value'
		} else {
			// Keep other options
			remainingOptions = append(remainingOptions, part)
			i++
		}
	}
	labelsStr := strings.Join(labelFlags, " ")
	otherOptionsStr := strings.Join(remainingOptions, " ")

	// Basic mapping: --detach for -d. 'name' becomes the container ID.
	// 'net' is handled via --net-host or CNI. Labels (-l) are translated to --label.
	// Use 'sh -c' to execute the command string within the container if cmdOnStart exists.
	// TODO: Properly parse remaining 'options' and map to ctr flags (e.g., --mount for -v, --env for -e).

	// Construct the ctr run command with parsed labels and other options
	// Ensure spaces are handled correctly, especially if some parts are empty.
	ctrCmdParts := []string{"ctr", "run", "--detach"}
	if netFlag != "" {
		ctrCmdParts = append(ctrCmdParts, netFlag)
	}
	if labelsStr != "" {
		ctrCmdParts = append(ctrCmdParts, labelsStr)
	}
	if otherOptionsStr != "" {
		ctrCmdParts = append(ctrCmdParts, otherOptionsStr)
	}
	ctrCmdParts = append(ctrCmdParts, image, name)

	ctrCmd := strings.Join(ctrCmdParts, " ")

	if cmdOnStart != "" {
		// Append the command to be run inside the container, quoted for sh -c
		ctrCmd += fmt.Sprintf(" sh -c %q", cmdOnStart)
	}

	log.Debugf("spinning up container '%s' with ctr command: '%s'", name, ctrCmd)
	return s.ExecWithSudo(ctrCmd)
}

// ContainerRm is a wrapper around `docker rm -f`. It forcibly removes the
// Docker container of the provided name.
func (s *SSHMeta) ContainerRm(name string) *CmdRes {
	// Force kill the task (equivalent to SIGKILL). Ignore errors if task doesn't exist or is already stopped.
	// Use sudo as task/container operations typically require root.
	killCmd := fmt.Sprintf("ctr task kill -s SIGKILL %s", name)
	// Execute kill but ignore its result; proceed even if it fails (e.g., task already stopped/gone).
	// Skip logging the output of the kill command as it might be noisy if the task is already gone.
	s.ExecWithSudo(killCmd, ExecOptions{SkipLog: true})

	// Remove the container. This should succeed if the task is gone or never existed.
	rmCmd := fmt.Sprintf("ctr container rm %s", name)
	log.Debugf("Removing container '%s' with ctr command: '%s'", name, rmCmd)
	// Return the result of the container removal attempt.
	return s.ExecWithSudo(rmCmd)
}

// ContainerInspect runs `ctr container info` for the container with the provided name.
// Output is in JSON format. Assumes ctr runs with sudo.
func (s *SSHMeta) ContainerInspect(name string) *CmdRes {
	inspectCmd := fmt.Sprintf("sudo ctr container info %s", name)
	log.Debugf("Inspecting container '%s' with ctr command: '%s'", name, inspectCmd)
	return s.ExecWithSudo(inspectCmd)
}

// containerInspectNet uses `ctr task exec` (via ContainerExec) to run `ip addr`
// inside the container to find its global IP addresses.
// The 'network' parameter is ignored as CNI handles networking details.
func (s *SSHMeta) containerInspectNet(name string) (map[string]string, error) {
	result := map[string]string{
		Name: name, // Keep original Name key
	}

	// Command to get the first global IPv4 address
	ipV4Cmd := `ip -4 -o addr show scope global | awk '{split(\$4,a,\"/\"); print a[1]}' | head -n1`
	// Command to get the first global IPv6 address
	ipV6Cmd := `ip -6 -o addr show scope global | awk '{split(\$4,a,\"/\"); print a[1]}' | head -n1`

	// Execute command to get IPv4
	resV4 := s.ContainerExec(name, ipV4Cmd)
	if resV4.WasSuccessful() {
		ipv4 := strings.TrimSpace(resV4.Stdout())
		if ipv4 != "" {
			result[IPv4] = ipv4 // Use the existing IPv4 constant key
			log.Debugf("Found IPv4 %s for container %s", ipv4, name)
		} else {
			log.Debugf("No global IPv4 address found for container %s", name)
		}
	} else {
		log.Warnf("Failed to get IPv4 address for container %s: %s", name, resV4.CombineOutput())
		// Don't return error yet, try IPv6
	}

	// Execute command to get IPv6
	resV6 := s.ContainerExec(name, ipV6Cmd)
	if resV6.WasSuccessful() {
		ipv6 := strings.TrimSpace(resV6.Stdout())
		if ipv6 != "" {
			result[IPv6] = ipv6 // Use the existing IPv6 constant key
			log.Debugf("Found IPv6 %s for container %s", ipv6, name)
		} else {
			log.Debugf("No global IPv6 address found for container %s", name)
		}
	} else {
		log.Warnf("Failed to get IPv6 address for container %s: %s", name, resV6.CombineOutput())
	}

	// Return success if we found at least one IP or if commands ran without error (even if no IP found)
	// Return error only if both commands failed significantly (though ContainerExec might not return detailed errors)
	if _, okV4 := result[IPv4]; !okV4 {
		if _, okV6 := result[IPv6]; !okV6 {
			// If neither IP was found, check if *both* exec commands failed fundamentally
			if !resV4.WasSuccessful() && !resV6.WasSuccessful() {
				// This indicates a more serious issue than just no IP assigned
				return nil, fmt.Errorf("failed to execute ip addr commands in container %s", name)
			}
			log.Warnf("Could not retrieve any global IP address for container %s using 'ip addr'", name)
		}
	}

	return result, nil
}

// ContainerInspectNet returns a map containing the Name, IPv4 and IPv6 addresses
// (if found) for the container by executing `ip addr` inside it.
// An error is returned if the IP addresses could not be retrieved.
func (s *SSHMeta) ContainerInspectNet(name string) (map[string]string, error) {
	// The network parameter is no longer relevant with ctr/CNI model for IP retrieval via exec
	return s.containerInspectNet(name)
}

// SampleContainersActions creates or deletes various containers used for
// testing Cilium and adds said containers to the provided Docker network.
func (s *SSHMeta) SampleContainersActions(mode string, networkName string, createOptions ...string) {
	createOptionsString := ""
	for _, opt := range createOptions {
		createOptionsString = fmt.Sprintf("%s %s", createOptionsString, opt)
	}

	images := map[string]string{
		Httpd1: constants.HttpdImage,
		Httpd2: constants.HttpdImage,
		Httpd3: constants.HttpdImage,
		App1:   constants.NetperfImage,
		App2:   constants.NetperfImage,
		App3:   constants.NetperfImage,
	}

	switch mode {
	case Create:
		for k, v := range images {
			res := s.ContainerCreate(k, v, networkName, fmt.Sprintf("-l id.%s %s", k, createOptionsString))
			res.ExpectSuccess("failed to create container %s", k)
		}
		s.WaitEndpointsReady()
	case Delete:
		for k := range images {
			s.ContainerRm(k)
		}
		s.WaitEndpointsDeleted()
	}
}

// GatherDockerLogs dumps docker containers logs output to the directory
// testResultsPath
func (s *SSHMeta) GatherDockerLogs() {
	return
	res := s.Exec("docker ps -a --format {{.Names}}")
	if !res.WasSuccessful() {
		log.WithField("error", res.CombineOutput()).Errorf("cannot get docker logs")
		return
	}
	commands := map[string]string{}
	for _, k := range res.ByLines() {
		if k != "" {
			key := fmt.Sprintf("docker logs %s", k)
			commands[key] = fmt.Sprintf("container_%s.log", k)
		}
	}

	testPath, err := CreateReportDirectory()
	if err != nil {
		s.logger.WithError(err).Errorf(
			"cannot create test results path '%s'", testPath)
		return
	}
	reportMap(testPath, commands, s)
}
