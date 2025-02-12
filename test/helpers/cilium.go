// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/test/config"
	ginkgoext "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers/logutils"
)

var log = logging.DefaultLogger

// BpfIPCacheList returns the output of `cilium-dbg bpf ipcache list -o json` as a map
// Key will be the CIDR (address with mask) and the value is the associated numeric security identity
func (s *SSHMeta) BpfIPCacheList(localScopeOnly bool) (map[string]uint32, error) {
	var (
		dump   map[string][]string
		result map[string]uint32
		res    *CmdRes
	)

	res = s.ExecCilium("bpf ipcache list -o json")

	if !res.WasSuccessful() {
		return nil, fmt.Errorf("cannot get bpf ipcache list: %s", res.CombineOutput())
	}
	err := res.Unmarshal(&dump)
	if err != nil {
		return nil, err
	}

	result = make(map[string]uint32, len(dump))
	for k, v := range dump {
		var nid uint32
		for _, s := range v {
			idWord := "identity="
			idIdx := strings.Index(s, idWord)
			if idIdx >= 0 {
				idIdx += len(idWord)
				endIdx := strings.Index(s[idIdx:], " ")
				if endIdx >= 0 {
					endIdx += idIdx
				} else {
					endIdx = len(s)
				}
				nid64, err := strconv.ParseUint(s[idIdx:endIdx], 10, 32)
				if err != nil {
					return nil, fmt.Errorf("cannot parse identity from: %s (%s): %w", s, s[idIdx:endIdx], err)
				}
				nid = uint32(nid64)
				if localScopeOnly && !identity.NumericIdentity(nid).HasLocalScope() {
					nid = 0
					continue
				}
			}
		}
		if nid != 0 {
			result[k] = nid
		}
	}

	return result, nil
}

// SelectedIdentities returns filtered identities from the output of `cilium-dbg policy selectors list
// -o json` as a string
func (s *SSHMeta) SelectedIdentities(match string) string {
	res := s.Exec(fmt.Sprintf(`cilium-dbg policy selectors list -o json | jq '.[] | select(.selector | test("%s")) | .identities[] | .'`, match))
	res.ExpectSuccess("Failed getting identities for %s selectors", match)
	return res.Stdout()
}

// ExecCilium runs a Cilium CLI command and returns the resultant cmdRes.
func (s *SSHMeta) ExecCilium(cmd string) *CmdRes {
	command := fmt.Sprintf("cilium-dbg %s", cmd)
	return s.ExecWithSudo(command)
}

// EndpointGet returns the output of `cilium-dbg endpoint get` for the provided
// endpoint ID.
func (s *SSHMeta) EndpointGet(id string) *models.Endpoint {
	if id == "" {
		return nil
	}
	var data []models.Endpoint
	endpointGetCmd := fmt.Sprintf("endpoint get %s -o json", id)
	res := s.ExecCilium(endpointGetCmd)
	err := res.Unmarshal(&data)
	if err != nil {
		s.logger.Error(
			"EndpointGet fail",
			slog.Any(logfields.Error, err),
			slog.String("id", id),
		)
		return nil
	}
	if len(data) > 0 {
		return &data[0]
	}
	return nil
}

// GetEndpointMutableConfigurationOption returns the value of the mutable
// configuration option optionName for the endpoint with ID endpointID, or an
// error if optionName's corresponding value cannot be retrieved for the
// endpoint.
func (s *SSHMeta) GetEndpointMutableConfigurationOption(endpointID, optionName string) (string, error) {
	cmd := fmt.Sprintf("endpoint config %s -o json | jq -r '.realized.options.%s'", endpointID, optionName)
	res := s.ExecCilium(cmd)
	if !res.WasSuccessful() {
		return "", fmt.Errorf("Unable to execute %q: %s", cmd, res.CombineOutput())
	}

	return res.SingleOut(), nil
}

// SetAndWaitForEndpointConfiguration waits for the endpoint configuration to become a certain value
func (s *SSHMeta) SetAndWaitForEndpointConfiguration(endpointID, optionName, expectedValue string) error {
	logAttrs := []any{
		slog.String(logfields.EndpointID, endpointID),
		slog.String("option", optionName),
		slog.String("value", expectedValue),
	}
	body := func() bool {
		s.logger.Info("Setting endpoint configuration", logAttrs...)
		status := s.EndpointSetConfig(endpointID, optionName, expectedValue)
		if !status {
			s.logger.Error("Cannot set endpoint configuration", logAttrs...)
			return status
		}

		value, err := s.GetEndpointMutableConfigurationOption(endpointID, optionName)
		if err != nil {
			log.Error("cannot get endpoint configuration", slog.Any(logfields.Error, err))
			return false
		}

		if value == expectedValue {
			return true
		}
		s.logger.With(
			slog.Any("expected", expectedValue),
			slog.Any("actual", value),
		).Debug(
			"Expected configuration option to have different value",
			logAttrs...,
		)
		return false
	}

	err := WithTimeout(
		body,
		fmt.Sprintf("cannot set endpoint config for endpoint %q", endpointID),
		&TimeoutConfig{Timeout: HelperTimeout})
	return err
}

// WaitEndpointsDeleted waits up until timeout reached for all endpoints to be
// deleted. Returns true if all endpoints have been deleted before HelperTimeout
// is exceeded, false otherwise.
func (s *SSHMeta) WaitEndpointsDeleted() bool {
	logAttr := slog.String("functionName", "WaitEndpointsDeleted")
	// cilium-health endpoint is always running, as is the host endpoint.
	desiredState := "2"
	body := func() bool {
		cmd := `cilium-dbg endpoint list -o json | jq '. | length'`
		res := s.Exec(cmd)
		numEndpointsRunning := strings.TrimSpace(res.Stdout())
		if numEndpointsRunning == desiredState {
			return true
		}

		s.logger.Info(
			"Endpoints are still running",
			slog.String("running", numEndpointsRunning),
			slog.String("desired", desiredState),
			logAttr,
		)
		return false
	}
	err := WithTimeout(body, "Endpoints are not deleted after timeout", &TimeoutConfig{Timeout: HelperTimeout})
	if err != nil {
		s.logger.Warn(
			"Endpoints are not deleted after timeout",
			slog.Any(logfields.Error, err),
			logAttr,
		)
		s.Exec("cilium-dbg endpoint list") // This function is only for debugging.
		return false
	}
	return true

}

// WaitDockerPluginReady waits up until timeout reached for Cilium docker plugin to be ready
func (s *SSHMeta) WaitDockerPluginReady() bool {
	logAttr := slog.String("functionName", "WaitDockerPluginReady")

	body := func() bool {
		// check that docker plugin socket exists
		cmd := `stat /run/docker/plugins/cilium.sock`
		res := s.ExecWithSudo(cmd)
		if !res.WasSuccessful() {
			return false
		}
		// check that connect works
		cmd = `nc -U -z /run/docker/plugins/cilium.sock`
		res = s.ExecWithSudo(cmd)
		return res.WasSuccessful()
	}
	err := WithTimeout(body, "Docker plugin is not ready after timeout", &TimeoutConfig{Timeout: HelperTimeout})
	if err != nil {
		s.logger.Warn("Docker plugin is not ready after timeout", slog.Any(logfields.Error, err), logAttr)
		s.ExecWithSudo("ls -l /run/docker/plugins/cilium.sock") // This function is only for debugginag.
		return false
	}
	return true
}

func (s *SSHMeta) MonitorDebug(on bool, epID string) bool {
	logAttr := slog.String("functionName", "MonitorDebug")
	dbg := "Disabled"
	mode := ""
	if on {
		dbg = "Enabled"
	}
	if epID != "" {
		mode = "endpoint"
	}

	res := s.ExecCilium(fmt.Sprintf("%s config %s Debug=%s", mode, epID, dbg))
	if !res.WasSuccessful() {
		s.logger.Error("cannot set BPF datapath debugging", slog.String("mode", strings.ToLower(dbg)), logAttr)
		return false
	}
	return true
}

// WaitEndpointsReady waits up until timeout reached for all endpoints to not be
// in any regenerating or waiting-for-identity state. Returns true if all
// endpoints regenerate before HelperTimeout is exceeded, false otherwise.
func (s *SSHMeta) WaitEndpointsReady() bool {
	logAttr := slog.String("functionName", "WaitEndpointsReady")
	desiredState := string(models.EndpointStateReady)
	body := func() bool {
		filter := `{range [*]}{@.id}{"="}{@.status.state},{@.status.identity.id}{"\n"}{end}`
		cmd := fmt.Sprintf(`cilium-dbg endpoint list -o jsonpath='%s'`, filter)

		res := s.Exec(cmd)
		if !res.WasSuccessful() {
			s.logger.Info("Cannot get endpoint list", slog.Any("command", res.CombineOutput()), logAttr)
			return false
		}
		values := res.KVOutput()
		total := len(values)

		result := map[string]int{}
		for _, status := range values {
			fields := strings.Split(status, ",")
			state := fields[0]
			secID := fields[1]
			// Consider an endpoint with reserved identity 5 (reserved:init) as not ready.
			if secID == "5" {
				state = state + "+init"
			}
			result[state]++
		}

		s.logger.Info(
			fmt.Sprintf("'%d' containers are in a '%s' state of a total of '%d' containers.",
				result[desiredState], desiredState, total),
			slog.Any("status", result),
			logAttr,
		)

		return result[desiredState] == total
	}

	err := WithTimeout(body, "Endpoints are not ready after timeout", &TimeoutConfig{Timeout: HelperTimeout})
	if err != nil {
		s.logger.Warn(
			"Endpoints are not ready after timeout",
			slog.Any(logfields.Error, err),
			logAttr,
		)
		s.Exec("cilium-dbg endpoint list") // This function is only for debugging into log.
		return false
	}
	return true
}

// EndpointSetConfig sets the provided configuration option to the provided
// value for the endpoint with the endpoint ID id. It returns true if the
// configuration update command returned successfully.
func (s *SSHMeta) EndpointSetConfig(id, option, value string) bool {
	logAttr := slog.String("endpointID", id)
	res := s.ExecCilium(fmt.Sprintf(
		"endpoint config %s -o json | jq -r '.realized.options.%s'", id, option))

	if res.SingleOut() == value {
		s.logger.Debug(
			"no need to update option, value already set",
			slog.String("option", option),
			slog.String("value", value),
			logAttr,
		)
		return res.WasSuccessful()
	}

	before := s.EndpointGet(id)
	if before == nil {
		return false
	}

	configCmd := fmt.Sprintf("endpoint config %s %s=%s", id, option, value)
	data := s.ExecCilium(configCmd)
	if !data.WasSuccessful() {
		s.logger.Error(
			"cannot set endpoint configuration option",
			slog.String("option", option),
			slog.String("value", value),
			logAttr,
		)
		return false
	}

	return true
}

// ListEndpoints returns the CmdRes resulting from executing
// `cilium-dbg endpoint list -o json`.
func (s *SSHMeta) ListEndpoints() *CmdRes {
	return s.ExecCilium("endpoint list -o json")
}

// GetEndpointsIDMap returns a mapping of an endpoint ID to Docker container
// name, and an error if the list of endpoints cannot be retrieved via the
// Cilium CLI.
func (s *SSHMeta) GetEndpointsIDMap() (map[string]string, error) {
	filter := `{range [*]}{@.id}{"="}{@.status.external-identifiers.container-name}{"\n"}{end}`
	cmd := fmt.Sprintf("endpoint list -o jsonpath='%s'", filter)
	endpoints := s.ExecCilium(cmd)
	if !endpoints.WasSuccessful() {
		return nil, fmt.Errorf("%q failed: %s", cmd, endpoints.CombineOutput())
	}
	return endpoints.KVOutput(), nil
}

// GetAllEndpointsIds returns a mapping of all Docker container name to to its
// corresponding endpoint ID, and an error if the list of endpoints cannot be
// retrieved via the Cilium CLI.
func (s *SSHMeta) GetAllEndpointsIds() (map[string]string, error) {
	filter := `{range [*]}{@.status.external-identifiers.container-name}{"="}{@.id}{"\n"}{end}`
	cmd := fmt.Sprintf("endpoint list -o jsonpath='%s'", filter)
	endpoints := s.ExecCilium(cmd)
	if !endpoints.WasSuccessful() {
		return nil, fmt.Errorf("%q failed: %s", cmd, endpoints.CombineOutput())
	}
	return endpoints.KVOutput(), nil
}

// GetEndpointsIds returns a mapping of a Docker container name to to its
// corresponding endpoint ID, and an error if the list of endpoints cannot be
// retrieved via the Cilium CLI.
func (s *SSHMeta) GetEndpointsIds() (map[string]string, error) {
	// cilium-dbg endpoint list -o jsonpath='{range [?(@.status.labels.security-relevant[0]!='reserved:health')]}{@.status.external-identifiers.container-name}{"="}{@.id}{"\n"}{end}'
	filter := `{range [?(@.status.labels.security-relevant[0]!="reserved:health")]}{@.status.external-identifiers.container-name}{"="}{@.id}{"\n"}{end}`
	cmd := fmt.Sprintf("endpoint list -o jsonpath='%s'", filter)
	endpoints := s.ExecCilium(cmd)
	if !endpoints.WasSuccessful() {
		return nil, fmt.Errorf("%q failed: %s", cmd, endpoints.CombineOutput())
	}
	return endpoints.KVOutput(), nil
}

// GetEndpointsIdentityIds returns a mapping of a Docker container name to it's
// corresponding endpoint's security identity, it will return an error if the list
// of endpoints cannot be retrieved via the Cilium CLI.
func (s *SSHMeta) GetEndpointsIdentityIds() (map[string]string, error) {
	filter := `{range [*]}{@.status.external-identifiers.container-name}{"="}{@.status.identity.id}{"\n"}{end}`
	endpoints := s.ExecCilium(fmt.Sprintf("endpoint list -o jsonpath='%s'", filter))
	if !endpoints.WasSuccessful() {
		return nil, fmt.Errorf("cannot get endpoint list: %s", endpoints.CombineOutput())
	}
	return endpoints.KVOutput(), nil
}

// GetEndpointsNames returns the container-name field of each Cilium endpoint.
func (s *SSHMeta) GetEndpointsNames() ([]string, error) {
	data := s.ListEndpoints()
	if !data.WasSuccessful() {
		return nil, fmt.Errorf("`cilium-dbg endpoint list` was not successful")
	}

	result, err := data.Filter("{ [?(@.status.labels.security-relevant[0]!='reserved:health')].status.external-identifiers.container-name }")
	if err != nil {
		return nil, err
	}

	return strings.Split(result.String(), " "), nil
}

// ManifestsPath returns the path of the directory where manifests (YAMLs
// containing policies, DaemonSets, etc.) are stored for the runtime tests.
// TODO: this can just be a constant; there's no need to have a function.
func (s *SSHMeta) ManifestsPath() string {
	return fmt.Sprintf("%s/runtime/manifests/", s.basePath)
}

func (s *SSHMeta) BasePath() string {
	return s.basePath
}

// MonitorStart starts the  monitor command in background and returns CmdREs and a callback
// function which stops the monitor when the user needs. When the callback is
// called the command will stop and monitor's output is saved on
// `monitorLogFileName` file.
func (s *SSHMeta) MonitorStart(opts ...string) (*CmdRes, func() error) {
	cmd := "cilium-dbg monitor -vv " + strings.Join(opts, " ") + " | ts '[%Y-%m-%d %H:%M:%S]'"
	ctx, cancel := context.WithCancel(context.Background())
	res := s.ExecInBackground(ctx, cmd, ExecOptions{SkipLog: true})

	cb := func() error {
		cancel()
		testPath, err := CreateReportDirectory()
		if err != nil {
			s.logger.Error(
				"cannot create test results path",
				slog.Any(logfields.Error, err),
				slog.String(logfields.Path, testPath),
			)
			return err
		}

		err = os.WriteFile(
			filepath.Join(testPath, MonitorLogFileName),
			res.CombineOutput().Bytes(),
			LogPerm)
		if err != nil {
			log.Error(
				"cannot create monitor log file",
				slog.Any(logfields.Error, err),
			)
		}
		return nil
	}
	return res, cb
}

// GetFullPath returns the path of file name prepended with the absolute path
// where manifests (YAMLs containing policies, DaemonSets, etc.) are stored.
func (s *SSHMeta) GetFullPath(name string) string {
	return fmt.Sprintf("%s%s", s.ManifestsPath(), name)
}

// SetPolicyEnforcement sets the PolicyEnforcement configuration value for the
// Cilium agent to the provided status.
func (s *SSHMeta) SetPolicyEnforcement(status string) *CmdRes {
	// We check before setting PolicyEnforcement; if we do not, EndpointWait
	// will fail due to the status of the endpoints not changing.
	log.Info(
		"setting policy policy enforcement",
		slog.Any(PolicyEnforcement, status),
	)
	res := s.ExecCilium("config -o json | jq -r '.status.realized[\"policy-enforcement\"]'")
	if res.SingleOut() == status {
		return res
	}
	return s.ExecCilium(fmt.Sprintf("config %s=%s", PolicyEnforcement, status))
}

// SetPolicyEnforcementAndWait and wait sets the PolicyEnforcement configuration
// value for the Cilium agent to the provided status, and then waits for all endpoints
// running in s to be ready. Returns whether setting of the configuration value
// was unsuccessful / if the endpoints go into ready state.
func (s *SSHMeta) SetPolicyEnforcementAndWait(status string) bool {
	res := s.SetPolicyEnforcement(status)
	if !res.WasSuccessful() {
		return false
	}

	return s.WaitEndpointsReady()
}

// PolicyDelAll deletes all policy rules currently imported into Cilium.
func (s *SSHMeta) PolicyDelAll() *CmdRes {
	log.Info("Deleting all policy in agent")
	return s.PolicyDel("--all")
}

// PolicyDel deletes the policy with the given ID from Cilium.
func (s *SSHMeta) PolicyDel(id string) *CmdRes {
	res := s.ExecCilium(fmt.Sprintf(
		"policy delete %s -o json | jq '.revision'", id))
	if !res.WasSuccessful() {
		return res
	}
	policyID, _ := res.IntOutput()
	return s.PolicyWait(policyID)
}

// PolicyGet runs `cilium-dbg policy get <id>`, where id is the name of a specific
// policy imported into Cilium. It returns the resultant CmdRes from running
// the aforementioned command.
func (s *SSHMeta) PolicyGet(id string) *CmdRes {
	return s.ExecCilium(fmt.Sprintf("policy get %s", id))
}

// PolicyGetAll gets all policies that are imported in the Cilium agent.
func (s *SSHMeta) PolicyGetAll() *CmdRes {
	return s.ExecCilium("policy get")

}

// PolicyGetRevision retrieves the current policy revision number in the Cilium
// agent.
func (s *SSHMeta) PolicyGetRevision() (int, error) {
	rev := s.ExecCilium("policy get -o json | jq '.revision'")
	return rev.IntOutput()
}

// PolicyImportAndWait validates and imports a new policy into Cilium and waits
// until the policy revision number increments. Returns an error if the policy
// is invalid or could not be imported.
func (s *SSHMeta) PolicyImportAndWait(path string, timeout time.Duration) (int, error) {
	ginkgoext.By(fmt.Sprintf("Setting up policy: %s", path))

	revision, err := s.PolicyGetRevision()
	if err != nil {
		return -1, fmt.Errorf("cannot get policy revision: %w", err)
	}

	s.logger.Info(
		"before importing policy",
		slog.String(logfields.Path, path),
		slog.Int(logfields.PolicyRevision, revision),
	)

	s.logger.Info(
		"validating policy before importing",
		slog.String(logfields.Path, path),
	)

	res := s.ExecCilium(fmt.Sprintf("policy validate %s", path))
	if !res.WasSuccessful() {
		s.logger.Error(
			"could not validate policy",
			slog.String(logfields.Path, path),
			slog.Any("output", res.CombineOutput()),
		)
		return -1, fmt.Errorf("could not validate policy %s: %s", path, res.CombineOutput())
	}

	res = s.ExecCilium(fmt.Sprintf("policy import %s", path))
	if !res.WasSuccessful() {
		s.logger.Error(
			"could not import policy",
			slog.String(logfields.Path, path),
			slog.Any("output", res.CombineOutput()),
		)
		return -1, fmt.Errorf("could not import policy %s", path)
	}
	body := func() bool {
		currentRev, _ := s.PolicyGetRevision()
		if currentRev > revision {
			res := s.PolicyWait(currentRev)
			if !res.WasSuccessful() {
				log.Error(
					"policy wait failed",
					slog.Any("output", res.CombineOutput()),
				)
			}
			return res.WasSuccessful()
		}
		s.logger.Info(
			"policy revisions are the same",
			slog.Int("policyRevisionAfterImport", revision),
			slog.Int(logfields.PolicyRevision, currentRev),
		)
		return false
	}
	err = WithTimeout(body, "could not import policy", &TimeoutConfig{Timeout: timeout})
	if err != nil {
		return -1, err
	}
	revision, err = s.PolicyGetRevision()
	s.logger.Info(
		"policy import finished and revision increased",
		slog.String(logfields.Path, path),
		slog.Int(logfields.PolicyRevision, revision),
	)
	return revision, err
}

// PolicyImport imports a new policy into Cilium.
func (s *SSHMeta) PolicyImport(path string) error {
	res := s.ExecCilium(fmt.Sprintf("policy import %s", path))
	if !res.WasSuccessful() {
		s.logger.Error(
			"could not import policy",
			slog.Any("command", res.CombineOutput()),
		)
		return fmt.Errorf("could not import policy %s", path)
	}
	return nil
}

// PolicyRenderAndImport receives an string with a policy, renders it in the
// test root directory and imports the policy to cilium. It returns the new
// policy id.  Returns an error if the file cannot be created or if the policy
// cannot be imported
func (s *SSHMeta) PolicyRenderAndImport(policy string) (int, error) {
	filename := fmt.Sprintf("policy_%s.json", MakeUID())
	s.logger.Debug(
		"PolicyRenderAndImport: render policy",
		slog.String("filename", filename),
	)
	err := s.RenderTemplateToFile(filename, policy, os.ModePerm)
	if err != nil {
		s.logger.Error(
			"PolicyRenderAndImport: cannot create policy file",
			slog.String("filename", filename),
		)
		return 0, fmt.Errorf("cannot render the policy: %w", err)
	}
	path := s.GetFilePath(filename)
	s.logger.Debug(
		"PolicyRenderAndImport: import policy",
		slog.String(logfields.Path, path),
	)
	defer os.Remove(filename)
	return s.PolicyImportAndWait(path, HelperTimeout)
}

// GetFilePath is a utility function which returns path to give fale relative to BasePath
func (s *SSHMeta) GetFilePath(filename string) string {
	return fmt.Sprintf("%s/%s", s.basePath, filename)
}

// PolicyWait executes `cilium-dbg policy wait`, which waits until all endpoints are
// updated to the given policy revision.
func (s *SSHMeta) PolicyWait(revisionNum int) *CmdRes {
	return s.ExecCilium(fmt.Sprintf("policy wait %d", revisionNum))
}

// ReportFailed gathers relevant Cilium runtime data and logs for debugging
// purposes.
func (s *SSHMeta) ReportFailed(commands ...string) {
	if config.CiliumTestConfig.SkipLogGathering {
		ginkgoext.GinkgoPrint("Skipped gathering logs (-cilium.skipLogs=true)\n")
		return
	}

	// Log the following line to both the log file, and to console to delineate
	// when log gathering begins.
	res := s.ExecCilium("endpoint list") // save the output in the logs
	ginkgoext.GinkgoPrint(res.GetDebugMessage())

	for _, cmd := range commands {
		res = s.ExecWithSudo(cmd, ExecOptions{SkipLog: true})
		ginkgoext.GinkgoPrint(res.GetDebugMessage())
	}

	s.DumpCiliumCommandOutput()
	s.GatherLogs()
	s.GatherDockerLogs()
}

// ValidateEndpointsAreCorrect is a function that validates that all Docker
// container that are in the given docker network are correct as cilium
// endpoints.
func (s *SSHMeta) ValidateEndpointsAreCorrect(dockerNetwork string) error {
	endpointsFilter := `{range[*]}{.status.external-identifiers.container-id}{"="}{.id}{"\n"}{end}`
	jqFilter := `.[].Containers|keys |.[]`

	res := s.Exec(fmt.Sprintf("docker network inspect %s | jq -r '%s'", dockerNetwork, jqFilter))
	if !res.WasSuccessful() {
		return errors.New("Cannot get Docker containers in the given network")
	}

	epRes := s.ExecCilium(fmt.Sprintf("endpoint list -o jsonpath='%s'", endpointsFilter))
	if !epRes.WasSuccessful() {
		return errors.New("Cannot get cilium endpoint list")
	}

	endpoints := epRes.KVOutput()
	for _, containerID := range res.ByLines() {
		_, exists := endpoints[containerID]
		if !exists {

			return fmt.Errorf("ContainerID %s is not present in the endpoint list", containerID)
		}
	}
	return nil
}

// ValidateNoErrorsInLogs checks in cilium logs since the given duration (By
// default `CurrentGinkgoTestDescription().Duration`) do not contain `panic`,
// `deadlocks` or `segmentation faults` messages . In case of any of these
// messages, it'll mark the test as failed.
func (s *SSHMeta) ValidateNoErrorsInLogs(duration time.Duration) {
	logsCmd := fmt.Sprintf(`sudo journalctl -au %s --since '%v seconds ago'`,
		DaemonName, duration.Seconds())
	logs := s.Exec(logsCmd, ExecOptions{SkipLog: true}).Stdout()

	defer func() {
		// Keep the cilium logs for the given test in a separate file.
		testPath, err := CreateReportDirectory()
		if err != nil {
			s.logger.Error(
				"Cannot create report directory",
				slog.Any(logfields.Error, err),
			)
			return
		}
		err = os.WriteFile(
			fmt.Sprintf("%s/%s", testPath, CiliumTestLog),
			[]byte(logs), LogPerm)

		if err != nil {
			s.logger.Error(
				"Cannot create "+CiliumTestLog,
				slog.Any(logfields.Error, err),
			)
		}
	}()

	blacklist := GetBadLogMessages()
	failIfContainsBadLogMsg(logs, "Cilium", blacklist)

	fmt.Fprint(CheckLogs, logutils.LogErrorsSummary(logs))
}

// PprofReport runs pprof each 5 minutes and saves the data into the test
// folder saved with pprof suffix.
func (s *SSHMeta) PprofReport() {
	PProfCadence := 5 * time.Minute
	ticker := time.NewTicker(PProfCadence)
	logAttrs := slog.String("subsys", "pprofReport")

	for range ticker.C {
		testPath, err := CreateReportDirectory()
		if err != nil {
			s.logger.Error(
				"cannot create test result path",
				slog.Any(logfields.Error, err),
				slog.String(logfields.Path, testPath),
				logAttrs,
			)
			return
		}
		d := time.Now().Add(50 * time.Second)
		ctx, cancel := context.WithDeadline(context.Background(), d)

		res := s.ExecInBackground(ctx, `sudo gops pprof-cpu $(pgrep cilium-agent)`)

		err = res.WaitUntilMatch("Profiling dump saved to")
		if err != nil {
			s.logger.Error("Cannot get pprof report", slog.Any(logfields.Error, err))
		}

		files := s.Exec("ls -1 /tmp/")
		for _, file := range files.ByLines() {
			if !strings.Contains(file, "profile") {
				continue
			}

			dest := filepath.Join(
				s.basePath, testPath,
				fmt.Sprintf("%s.pprof", file))
			_ = s.ExecWithSudo(fmt.Sprintf("mv /tmp/%s %s", file, dest))
		}
		cancel()
	}
}

// DumpCiliumCommandOutput runs a variety of Cilium CLI commands and dumps their
// output to files. These files are gathered as part of each Jenkins job for
// postmortem debugging of build failures.
func (s *SSHMeta) DumpCiliumCommandOutput() {

	testPath, err := CreateReportDirectory()
	if err != nil {
		s.logger.Error(
			"cannot create test result path",
			slog.Any(logfields.Error, err),
			slog.String(logfields.Path, testPath),
		)
		return
	}
	reportMap(testPath, ciliumCLICommands, s)

	// No need to create file for bugtool because it creates an archive of files
	// for us.
	res := s.ExecWithSudo(
		fmt.Sprintf("%s %s -t %q", CiliumBugtool, CiliumBugtoolArgs, filepath.Join(s.basePath, testPath)),
		ExecOptions{SkipLog: true})
	if !res.WasSuccessful() {
		s.logger.Error(
			"Error running bugtool",
			slog.Any("output", res.CombineOutput()),
		)
	}

}

// GatherLogs dumps Cilium, Cilium Docker, key-value store logs, and gops output
// to the directory testResultsPath
func (s *SSHMeta) GatherLogs() {
	ciliumLogCommands := map[string]string{
		fmt.Sprintf("sudo journalctl -au %s --no-pager", DaemonName):             "cilium.log",
		fmt.Sprintf("sudo journalctl -au %s --no-pager", CiliumDockerDaemonName): "cilium-docker.log",
	}

	testPath, err := CreateReportDirectory()
	if err != nil {
		s.logger.Error(
			"cannot create test results path",
			slog.Any(logfields.Error, err),
			slog.String(logfields.Path, testPath),
		)
		return
	}
	reportMap(testPath, ciliumLogCommands, s)

	ciliumStateCommands := []string{
		fmt.Sprintf("sudo rsync -rv --exclude=*.sock %s %s", RunDir, filepath.Join(s.basePath, testPath, "lib")),
		fmt.Sprintf("sudo rsync -rv --exclude=*.sock %s %s", LibDir, filepath.Join(s.basePath, testPath, "run")),
		fmt.Sprintf("sudo mv /tmp/core* %s", filepath.Join(s.basePath, testPath)),
	}

	for _, cmd := range ciliumStateCommands {
		res := s.Exec(cmd, ExecOptions{SkipLog: true})
		if !res.WasSuccessful() {
			s.logger.Error(
				"cannot gather files for cmd",
				slog.Any("cmd", cmd),
				slog.Any("output", res.CombineOutput()),
			)
		}
	}
}

// SetUpCilium sets up Cilium as a systemd service with a hardcoded set of options. It
// returns an error if any of the operations needed to start Cilium fails.
func (s *SSHMeta) SetUpCilium() error {
	return s.SetUpCiliumWithOptions("")
}

// SetUpCiliumWithOptions sets up Cilium as a systemd service with a given set of options. It
// returns an error if any of the operations needed to start Cilium fail.
func (s *SSHMeta) SetUpCiliumWithOptions(ciliumOpts string) error {
	// Default kvstore options
	if !strings.Contains(ciliumOpts, "--kvstore") {
		ciliumOpts += " --kvstore etcd --kvstore-opt etcd.address=127.0.0.1:4001"
	}

	ciliumOpts += " --exclude-local-address=" + DockerBridgeIP + "/32"
	ciliumOpts += " --exclude-local-address=" + FakeIPv4WorldAddress + "/32"
	ciliumOpts += " --exclude-local-address=" + FakeIPv6WorldAddress + "/128"
	if config.CiliumTestConfig.CiliumExtraOpts != "" {
		ciliumOpts += " " + config.CiliumTestConfig.CiliumExtraOpts
	}

	// Get the current CILIUM_IMAGE from the service definition
	res := s.Exec("grep CILIUM_IMAGE= /etc/sysconfig/cilium")
	if !res.WasSuccessful() {
		return fmt.Errorf("Could not find CILIUM_IMAGE from /etc/sysconfig/cilium: %s", res.CombineOutput())
	}
	ciliumImage := res.Stdout()

	systemdTemplate := `
PATH=/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/sbin:/sbin:/bin
%s
CILIUM_OPTS=--debug --pprof=true --log-system-load %s
INITSYSTEM=SYSTEMD`

	ciliumConfig := "cilium.conf.ginkgo"
	err := s.RenderTemplateToFile(ciliumConfig, fmt.Sprintf(systemdTemplate, ciliumImage, ciliumOpts), os.ModePerm)
	if err != nil {
		return err
	}

	confPath := s.GetFilePath(ciliumConfig)
	res = s.Exec(fmt.Sprintf("sudo cp %s /etc/sysconfig/cilium", confPath))
	if !res.WasSuccessful() {
		return fmt.Errorf("%s", res.CombineOutput())
	}
	res = s.Exec("sudo systemctl restart cilium")
	if !res.WasSuccessful() {
		return fmt.Errorf("%s", res.CombineOutput())
	}
	return nil
}

func (s *SSHMeta) SetUpCiliumWithHubble() error {
	return s.SetUpCiliumWithOptions("--enable-hubble")
}

// WaitUntilReady waits until the output of `cilium-dbg status` returns with code
// zero. Returns an error if the output of `cilium-dbg status` returns a nonzero
// return code after the specified timeout duration has elapsed.
func (s *SSHMeta) WaitUntilReady(timeout time.Duration) error {

	body := func() bool {
		res := s.ExecCilium("status")
		s.logger.Info(
			"Cilium status result",
			slog.Bool("status", res.WasSuccessful()),
		)
		return res.WasSuccessful()
	}
	err := WithTimeout(body, "Cilium is not ready", &TimeoutConfig{Timeout: timeout})
	return err
}

// RestartCilium reloads cilium on this host, then waits for it to become
// ready again.
func (s *SSHMeta) RestartCilium() error {
	ginkgoext.By("Restarting Cilium")

	res := s.ExecWithSudo("systemctl restart cilium")
	if !res.WasSuccessful() {
		return fmt.Errorf("%s", res.CombineOutput())
	}
	if err := s.WaitUntilReady(CiliumStartTimeout); err != nil {
		return err
	}
	if !s.WaitEndpointsReady() {
		return fmt.Errorf("Endpoints are not ready after timeout")
	}
	return nil
}

// AddIPToLoopbackDevice adds the specified IP (assumed to be in form <ip>/<mask>)
// to the loopback device on s.
func (s *SSHMeta) AddIPToLoopbackDevice(ip string) *CmdRes {
	return s.ExecWithSudo(fmt.Sprintf("ip addr add dev lo %s", ip))
}

// RemoveIPFromLoopbackDevice removes the specified IP (assumed to be in form <ip>/<mask>)
// from the loopback device on s.
func (s *SSHMeta) RemoveIPFromLoopbackDevice(ip string) *CmdRes {
	return s.ExecWithSudo(fmt.Sprintf("ip addr del dev lo %s", ip))
}

// FlushGlobalConntrackTable flushes the global connection tracking table.
func (s *SSHMeta) FlushGlobalConntrackTable() *CmdRes {
	return s.ExecCilium("bpf ct flush global")
}
