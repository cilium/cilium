// Copyright 2017-2020 Authors of Cilium
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

package helpers

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/test/config"
	ginkgoext "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers/logutils"

	"github.com/sirupsen/logrus"
)

var log = logging.DefaultLogger

const (
	// MaxRetries is the number of times that a loop should iterate until a
	// specified condition is not met
	MaxRetries = 30
)

// BpfLBList returns the output of `cilium bpf lb list -o json` as a map
// Key will be the frontend address and the value is an array with all backend
// addresses
func (s *SSHMeta) BpfLBList(noDuplicates bool) (map[string][]string, error) {
	var (
		result map[string][]string
		res    *CmdRes
	)

	res = s.ExecCilium("bpf lb list -o json")

	if !res.WasSuccessful() {
		return nil, fmt.Errorf("cannot get bpf lb list: %s", res.CombineOutput())
	}
	err := res.Unmarshal(&result)
	if err != nil {
		return nil, err
	}

	if noDuplicates {
		for svc, entries := range result {
			unique := make(map[string]struct{})
			for _, e := range entries {
				unique[e] = struct{}{}
			}
			result[svc] = make([]string, 0, len(unique))
			for e := range unique {
				result[svc] = append(result[svc], e)
			}
		}
	}

	return result, nil
}

// ExecCilium runs a Cilium CLI command and returns the resultant cmdRes.
func (s *SSHMeta) ExecCilium(cmd string) *CmdRes {
	command := fmt.Sprintf("cilium %s", cmd)
	return s.ExecWithSudo(command)
}

// EndpointGet returns the output of `cilium endpoint get` for the provided
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
		s.logger.WithError(err).Errorf("EndpointGet fail %s", id)
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
	logger := s.logger.WithFields(logrus.Fields{
		logfields.EndpointID: endpointID,
		"option":             optionName,
		"value":              expectedValue})
	body := func() bool {
		logger.Infof("Setting endpoint configuration")
		status := s.EndpointSetConfig(endpointID, optionName, expectedValue)
		if !status {
			logger.Error("Cannot set endpoint configuration")
			return status
		}

		value, err := s.GetEndpointMutableConfigurationOption(endpointID, optionName)
		if err != nil {
			log.WithError(err).Error("cannot get endpoint configuration")
			return false
		}

		if value == expectedValue {
			return true
		}
		logger.Debugf("Expected configuration option to have value %s, but got %s",
			expectedValue, value)
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
	logger := s.logger.WithFields(logrus.Fields{"functionName": "WaitEndpointsDeleted"})
	// cilium-health endpoint is always running, as is the host endpoint.
	desiredState := "2"
	body := func() bool {
		cmd := `cilium endpoint list -o json | jq '. | length'`
		res := s.Exec(cmd)
		numEndpointsRunning := strings.TrimSpace(res.Stdout())
		if numEndpointsRunning == desiredState {
			return true
		}

		logger.Infof("%s endpoints are still running, want %s", numEndpointsRunning, desiredState)
		return false
	}
	err := WithTimeout(body, "Endpoints are not deleted after timeout", &TimeoutConfig{Timeout: HelperTimeout})
	if err != nil {
		logger.WithError(err).Warn("Endpoints are not deleted after timeout")
		s.Exec("cilium endpoint list") // This function is only for debugging.
		return false
	}
	return true

}

func (s *SSHMeta) MonitorDebug(on bool, epID string) bool {
	logger := s.logger.WithFields(logrus.Fields{"functionName": "MonitorDebug"})
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
		logger.Errorf("cannot set BPF datapath debugging to %s", strings.ToLower(dbg))
		return false
	}
	return true
}

// WaitEndpointsReady waits up until timeout reached for all endpoints to not be
// in any regenerating or waiting-for-identity state. Returns true if all
// endpoints regenerate before HelperTimeout is exceeded, false otherwise.
func (s *SSHMeta) WaitEndpointsReady() bool {
	logger := s.logger.WithFields(logrus.Fields{"functionName": "WaitEndpointsReady"})
	desiredState := string(models.EndpointStateReady)
	body := func() bool {
		filter := `{range [*]}{@.status.external-identifiers.container-name}{"="}{@.status.state},{@.status.identity.id}{"\n"}{end}`
		cmd := fmt.Sprintf(`cilium endpoint list -o jsonpath='%s'`, filter)

		res := s.Exec(cmd)
		if !res.WasSuccessful() {
			logger.Infof("Cannot get endpoint list: %s", res.CombineOutput())
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

		logger.WithField("status", result).Infof(
			"'%d' containers are in a '%s' state of a total of '%d' containers.",
			result[desiredState], desiredState, total)

		if result[desiredState] == total {
			return true
		}

		return false
	}

	err := WithTimeout(body, "Endpoints are not ready after timeout", &TimeoutConfig{Timeout: HelperTimeout})
	if err != nil {
		logger.WithError(err).Warn("Endpoints are not ready after timeout")
		s.Exec("cilium endpoint list") // This function is only for debugging into log.
		return false
	}
	return true
}

// EndpointSetConfig sets the provided configuration option to the provided
// value for the endpoint with the endpoint ID id. It returns true if the
// configuration update command returned successfully.
func (s *SSHMeta) EndpointSetConfig(id, option, value string) bool {
	logger := s.logger.WithFields(logrus.Fields{"endpointID": id})
	res := s.ExecCilium(fmt.Sprintf(
		"endpoint config %s -o json | jq -r '.realized.options.%s'", id, option))

	if res.SingleOut() == value {
		logger.Debugf("no need to update %s=%s; value already set", option, value)
		return res.WasSuccessful()
	}

	before := s.EndpointGet(id)
	if before == nil {
		return false
	}

	configCmd := fmt.Sprintf("endpoint config %s %s=%s", id, option, value)
	data := s.ExecCilium(configCmd)
	if !data.WasSuccessful() {
		logger.Errorf("cannot set endpoint configuration %s=%s", option, value)
		return false
	}

	return true
}

// ListEndpoints returns the CmdRes resulting from executing
// `cilium endpoint list -o json`.
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
	// cilium endpoint list -o jsonpath='{range [?(@.status.labels.security-relevant[0]!='reserved:health')]}{@.status.external-identifiers.container-name}{"="}{@.id}{"\n"}{end}'
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
	if data.WasSuccessful() == false {
		return nil, fmt.Errorf("`cilium endpoint list` was not successful")
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
	cmd := "cilium monitor -vv " + strings.Join(opts, " ") + " | ts '[%Y-%m-%d %H:%M:%S]'"
	ctx, cancel := context.WithCancel(context.Background())
	res := s.ExecInBackground(ctx, cmd, ExecOptions{SkipLog: true})

	cb := func() error {
		cancel()
		testPath, err := CreateReportDirectory()
		if err != nil {
			s.logger.WithError(err).Errorf(
				"cannot create test results path '%s'", testPath)
			return err
		}

		err = ioutil.WriteFile(
			filepath.Join(testPath, MonitorLogFileName),
			res.CombineOutput().Bytes(),
			LogPerm)
		if err != nil {
			log.WithError(err).Errorf("cannot create monitor log file")
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

// PolicyEndpointsSummary returns the count of whether policy enforcement is
// enabled, disabled, and the total number of endpoints, and an error if the
// Cilium endpoint metadata cannot be retrieved via the API.
func (s *SSHMeta) PolicyEndpointsSummary() (map[string]int, error) {
	result := map[string]int{
		Enabled:  0,
		Disabled: 0,
		Total:    0,
	}

	res := s.ListEndpoints()
	if !res.WasSuccessful() {
		return nil, fmt.Errorf("was not able to list endpoints: %s", res.CombineOutput().String())
	}

	endpoints, err := res.Filter("{ [?(@.status.labels.security-relevant[0]!='reserved:health')].status.policy.realized.policy-enabled }")

	if err != nil {
		return result, fmt.Errorf(`cannot filter for "policy-enabled" from output of "cilium endpoint list"`)
	}
	status := strings.Split(endpoints.String(), " ")
	for _, kind := range status {
		switch models.EndpointPolicyEnabled(kind) {
		case models.EndpointPolicyEnabledBoth, models.EndpointPolicyEnabledEgress,
			models.EndpointPolicyEnabledIngress:
			result[Enabled]++
		case OptionNone:
			result[Disabled]++
		}
		result[Total]++
	}
	return result, nil
}

// SetPolicyEnforcement sets the PolicyEnforcement configuration value for the
// Cilium agent to the provided status.
func (s *SSHMeta) SetPolicyEnforcement(status string) *CmdRes {
	// We check before setting PolicyEnforcement; if we do not, EndpointWait
	// will fail due to the status of the endpoints not changing.
	log.Infof("setting %s=%s", PolicyEnforcement, status)
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

// PolicyGet runs `cilium policy get <id>`, where id is the name of a specific
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
		return -1, fmt.Errorf("cannot get policy revision: %s", err)
	}
	s.logger.WithFields(logrus.Fields{
		logfields.Path:           path,
		logfields.PolicyRevision: revision}).Info("before importing policy")

	s.logger.WithFields(logrus.Fields{
		logfields.Path: path}).Info("validating policy before importing")

	res := s.ExecCilium(fmt.Sprintf("policy validate %s", path))
	if res.WasSuccessful() == false {
		s.logger.WithFields(logrus.Fields{
			logfields.Path: path,
		}).Errorf("could not validate policy %s: %s", path, res.CombineOutput())
		return -1, fmt.Errorf("could not validate policy %s: %s", path, res.CombineOutput())
	}

	res = s.ExecCilium(fmt.Sprintf("policy import %s", path))
	if res.WasSuccessful() == false {
		s.logger.WithFields(logrus.Fields{
			logfields.Path: path,
		}).Errorf("could not import policy: %s", res.CombineOutput())
		return -1, fmt.Errorf("could not import policy %s", path)
	}
	body := func() bool {
		currentRev, _ := s.PolicyGetRevision()
		if currentRev > revision {
			res := s.PolicyWait(currentRev)
			if !res.WasSuccessful() {
				log.Errorf("policy wait failed: %s", res.CombineOutput())
			}
			return res.WasSuccessful()
		}
		s.logger.WithFields(logrus.Fields{
			logfields.PolicyRevision:    currentRev,
			"policyRevisionAfterImport": revision,
		}).Infof("policy revisions are the same")
		return false
	}
	err = WithTimeout(body, "could not import policy", &TimeoutConfig{Timeout: timeout})
	if err != nil {
		return -1, err
	}
	revision, err = s.PolicyGetRevision()
	s.logger.WithFields(logrus.Fields{
		logfields.Path:           path,
		logfields.PolicyRevision: revision,
	}).Infof("policy import finished and revision increased")
	return revision, err
}

// PolicyImport imports a new policy into Cilium.
func (s *SSHMeta) PolicyImport(path string) error {
	res := s.ExecCilium(fmt.Sprintf("policy import %s", path))
	if !res.WasSuccessful() {
		s.logger.Errorf("could not import policy: %s", res.CombineOutput())
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
	s.logger.Debugf("PolicyRenderAndImport: render policy to '%s'", filename)
	err := s.RenderTemplateToFile(filename, policy, os.ModePerm)
	if err != nil {
		s.logger.Errorf("PolicyRenderAndImport: cannot create policy file on '%s'", filename)
		return 0, fmt.Errorf("cannot render the policy:  %s", err)
	}
	path := s.GetFilePath(filename)
	s.logger.Debugf("PolicyRenderAndImport: import policy from '%s'", path)
	defer os.Remove(filename)
	return s.PolicyImportAndWait(path, HelperTimeout)
}

// GetFilePath is a utility function which returns path to give fale relative to BasePath
func (s *SSHMeta) GetFilePath(filename string) string {
	return fmt.Sprintf("%s/%s", s.basePath, filename)
}

// PolicyWait executes `cilium policy wait`, which waits until all endpoints are
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
			s.logger.WithError(err).Error("Cannot create report directory")
			return
		}
		err = ioutil.WriteFile(
			fmt.Sprintf("%s/%s", testPath, CiliumTestLog),
			[]byte(logs), LogPerm)

		if err != nil {
			s.logger.WithError(err).Errorf("Cannot create %s", CiliumTestLog)
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
	log := s.logger.WithField("subsys", "pprofReport")

	for {
		select {
		case <-ticker.C:

			testPath, err := CreateReportDirectory()
			if err != nil {
				log.WithError(err).Errorf("cannot create test result path '%s'", testPath)
				return
			}
			d := time.Now().Add(50 * time.Second)
			ctx, cancel := context.WithDeadline(context.Background(), d)

			res := s.ExecInBackground(ctx, `sudo gops pprof-cpu $(pgrep cilium-agent)`)

			err = res.WaitUntilMatch("Profiling dump saved to")
			if err != nil {
				log.WithError(err).Error("Cannot get pprof report")
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
}

// DumpCiliumCommandOutput runs a variety of Cilium CLI commands and dumps their
// output to files. These files are gathered as part of each Jenkins job for
// postmortem debugging of build failures.
func (s *SSHMeta) DumpCiliumCommandOutput() {

	testPath, err := CreateReportDirectory()
	if err != nil {
		s.logger.WithError(err).Errorf(
			"cannot create test results path '%s'", testPath)
		return
	}
	reportMap(testPath, ciliumCLICommands, s)

	// No need to create file for bugtool because it creates an archive of files
	// for us.
	res := s.ExecWithSudo(
		fmt.Sprintf("%s -t %s", CiliumBugtool, filepath.Join(s.basePath, testPath)),
		ExecOptions{SkipLog: true})
	if !res.WasSuccessful() {
		s.logger.Errorf("Error running bugtool: %s", res.CombineOutput())
	}

}

// GatherLogs dumps Cilium, Cilium Docker, key-value store logs, and gops output
// to the directory testResultsPath
func (s *SSHMeta) GatherLogs() {
	ciliumLogCommands := map[string]string{
		fmt.Sprintf("sudo journalctl -au %s --no-pager", DaemonName):             "cilium.log",
		fmt.Sprintf("sudo journalctl -au %s --no-pager", CiliumDockerDaemonName): "cilium-docker.log",
		"sudo docker logs cilium-consul":                                         "consul.log",
	}

	testPath, err := CreateReportDirectory()
	if err != nil {
		s.logger.WithError(err).Errorf(
			"cannot create test results path '%s'", testPath)
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
			s.logger.Errorf("cannot gather files for cmd '%s': %s", cmd, res.CombineOutput())
		}
	}
}

// ServiceAdd creates a new Cilium service with the provided ID, frontend,
// backends. Returns the result of creating said service.
func (s *SSHMeta) ServiceAdd(id int, frontend string, backends []string) *CmdRes {
	cmd := fmt.Sprintf(
		"service update --frontend '%s' --backends '%s' --id '%d'",
		frontend, strings.Join(backends, ","), id)
	return s.ExecCilium(cmd)
}

// ServiceIsSynced checks that the Cilium service with the specified id has its
// metadata match that of the load balancer BPF maps
func (s *SSHMeta) ServiceIsSynced(id int) (bool, error) {
	var svc *models.Service
	svcRes := s.ServiceGet(id)
	if !svcRes.WasSuccessful() {
		return false, fmt.Errorf("cannot get service id %d: %s", id, svcRes.CombineOutput())
	}
	err := svcRes.Unmarshal(&svc)
	if err != nil {
		return false, err
	}

	bpfLB, err := s.BpfLBList(false)
	if err != nil {
		return false, err
	}

	frontendAddr := serviceAddressKey(
		svc.Status.Realized.FrontendAddress.IP,
		fmt.Sprintf("%d", svc.Status.Realized.FrontendAddress.Port),
		svc.Status.Realized.FrontendAddress.Protocol,
		"",
	)
	lb, ok := bpfLB[frontendAddr]
	if ok == false {
		return false, fmt.Errorf(
			"frontend address from the service %d does not have it's corresponding frontend address(%s) on bpf maps",
			id, frontendAddr)
	}

	for _, backendAddr := range svc.Status.Realized.BackendAddresses {
		result := false
		backendSVC := net.JoinHostPort(
			*backendAddr.IP,
			fmt.Sprintf("%d", backendAddr.Port))
		target := fmt.Sprintf("%s (%d)", backendSVC, id)

		for _, addr := range lb {
			if addr == target {
				result = true
			}
		}
		if result == false {
			return false, fmt.Errorf(
				"backend address %s does not exists on BPF load balancer metadata id=%d", target, id)
		}
	}
	return true, nil
}

// ServiceList returns the output of  `cilium service list`
func (s *SSHMeta) ServiceList() *CmdRes {
	return s.ExecCilium("service list -o json")
}

// ServiceGet is a wrapper around `cilium service get <id>`. It returns the
// result of retrieving said service.
func (s *SSHMeta) ServiceGet(id int) *CmdRes {
	return s.ExecCilium(fmt.Sprintf("service get '%d' -o json", id))
}

// ServiceGetFrontendAddress returns a string with the frontend address and
// port. It returns an error if the ID cannot be retrieved.
func (s *SSHMeta) ServiceGetFrontendAddress(id int) (string, error) {

	var svc *models.Service
	res := s.ServiceGet(id)
	if !res.WasSuccessful() {
		return "", fmt.Errorf("Cannot get service id %d: %s", id, res.CombineOutput())
	}

	err := res.Unmarshal(&svc)
	if err != nil {
		return "", err
	}

	frontendAddress := net.JoinHostPort(
		svc.Status.Realized.FrontendAddress.IP,
		fmt.Sprintf("%d", svc.Status.Realized.FrontendAddress.Port))
	return frontendAddress, nil
}

// ServiceGetIds returns an array with the IDs of all Cilium services. Returns
// an error if the IDs cannot be retrieved
func (s *SSHMeta) ServiceGetIds() ([]string, error) {
	filter := `{range [*]}{@.status.realized.id}{"\n"}{end}`
	res, err := s.ServiceList().Filter(filter)
	if err != nil {
		return nil, err
	}
	// trim the trailing \n
	trimmed := strings.Trim(res.String(), "\n")
	return strings.Split(trimmed, "\n"), nil
}

// ServiceDel is a wrapper around `cilium service delete <id>`. It returns the
// result of deleting said service.
func (s *SSHMeta) ServiceDel(id int) *CmdRes {
	return s.ExecCilium(fmt.Sprintf("service delete '%d'", id))
}

// ServiceDelAll is a wrapper around `cilium service delete --all`. It returns the
// result of the command.
func (s *SSHMeta) ServiceDelAll() *CmdRes {
	return s.ExecCilium("service delete --all")
}

// SetUpCilium sets up Cilium as a systemd service with a hardcoded set of options. It
// returns an error if any of the operations needed to start Cilium fails.
func (s *SSHMeta) SetUpCilium() error {
	return s.SetUpCiliumWithOptions("")
}

// SetUpCiliumWithOptions sets up Cilium as a systemd service with a given set of options. It
// returns an error if any of the operations needed to start Cilium fail.
func (s *SSHMeta) SetUpCiliumWithOptions(ciliumOpts string) error {
	ciliumOpts += " --exclude-local-address=" + DockerBridgeIP + "/32"
	ciliumOpts += " --exclude-local-address=" + FakeIPv4WorldAddress + "/32"
	ciliumOpts += " --exclude-local-address=" + FakeIPv6WorldAddress + "/128"

	systemdTemplate := `
PATH=/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/sbin:/sbin:/bin
CILIUM_OPTS=--kvstore consul --kvstore-opt consul.address=127.0.0.1:8500 --debug --pprof=true --log-system-load %s
INITSYSTEM=SYSTEMD`

	ciliumConfig := "cilium.conf.ginkgo"
	err := s.RenderTemplateToFile(ciliumConfig, fmt.Sprintf(systemdTemplate, ciliumOpts), os.ModePerm)
	if err != nil {
		return err
	}

	confPath := filepath.Join("/home/vagrant/go/src/github.com/cilium/cilium/test", ciliumConfig)
	res := s.Exec(fmt.Sprintf("sudo cp %s /etc/sysconfig/cilium", confPath))
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

func (s *SSHMeta) SetUpCiliumWithSockops() error {
	return s.SetUpCiliumWithOptions("--sockops-enable")
}

// WaitUntilReady waits until the output of `cilium status` returns with code
// zero. Returns an error if the output of `cilium status` returns a nonzero
// return code after the specified timeout duration has elapsed.
func (s *SSHMeta) WaitUntilReady(timeout time.Duration) error {

	body := func() bool {
		res := s.ExecCilium("status")
		s.logger.Infof("Cilium status is %t", res.WasSuccessful())
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
