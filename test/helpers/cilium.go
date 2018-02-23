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

package helpers

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/onsi/ginkgo"
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
func (s *SSHMeta) BpfLBList() (map[string][]string, error) {
	var result map[string][]string

	res := s.ExecCilium("bpf lb list -o json")
	if !res.WasSuccessful() {
		return nil, fmt.Errorf("cannot get bpf lb list: %s", res.CombineOutput())
	}
	err := res.Unmarshal(&result)
	if err != nil {
		return nil, err
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
	endpointGetCmd := fmt.Sprintf("endpoint get %s", id)
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
func (s *SSHMeta) GetEndpointMutableConfigurationOption(endpointID, optionName string) (configurationOptionValue string, err error) {
	endpointModel := s.EndpointGet(endpointID)
	if endpointModel == nil {
		return "", fmt.Errorf("endpoint model for endpoint %s is nil", endpointID)
	}

	endpointConfiguration := endpointModel.Configuration
	if endpointConfiguration == nil {
		return "", fmt.Errorf("nil configuration of endpoint %s", endpointID)
	}

	// Endpoint currently only has mutable options.
	configurationOptionValue, configOptionExists := endpointModel.Configuration.Mutable[optionName]
	if !configOptionExists {
		return "", fmt.Errorf("provided configuration option %s does not exist in endpoint %s configuration", optionName, endpointID)
	}

	return configurationOptionValue, nil
}

// EndpointStatusLog returns the status log API model for the specified endpoint.
// Returns nil if no endpoint corresponds to the provided ID.
func (s *SSHMeta) EndpointStatusLog(id string) *models.EndpointStatusLog {
	if id == "" {
		return nil
	}

	var epStatusLog models.EndpointStatusLog

	endpointLogCmd := fmt.Sprintf("endpoint log %s", id)
	res := s.ExecCilium(endpointLogCmd)
	err := res.Unmarshal(&epStatusLog)
	if err != nil {
		s.logger.WithFields(logrus.Fields{"endpointID": id}).WithError(err).Errorf("unable to get endpoint status log")
		return nil
	}
	return &epStatusLog
}

// WaitEndpointRegenerated attempts up until MaxRetries are exceeded for the
// endpoint with the specified ID to be in "ready" state. Returns false if
// no such endpoint corresponds to the given id or if MaxRetries are exceeded.
func (s *SSHMeta) WaitEndpointRegenerated(id string) bool {
	logger := s.logger.WithFields(logrus.Fields{
		"functionName": "WaitEndpointRegenerated",
		"id":           id,
	})

	counter := 0
	desiredState := models.EndpointStateReady

	endpoint := s.EndpointGet(id)
	if endpoint == nil {
		return false
	}

	epState := endpoint.State

	for ; epState != desiredState && counter < MaxRetries; counter++ {

		logger.WithFields(logrus.Fields{
			"endpointState": epState,
		}).Info("endpoint not ready")

		logger.Infof("still within retry limit for waiting for endpoint to be in %s state; sleeping and checking again", desiredState)
		Sleep(1)

		endpoint = s.EndpointGet(id)
		if endpoint == nil {
			return false
		}
		epState = endpoint.State
	}

	if counter > MaxRetries {
		logger.Infof("%d retries have been exceeded for waiting for endpoint to be %s", MaxRetries, desiredState)
		return false
	}

	return true
}

// WaitEndpointsDeleted waits up until timeout reached for all endpoints to be
// deleted. Returns true if all endpoints have been deleted before HelperTimeout
// is exceeded, false otherwise.
func (s *SSHMeta) WaitEndpointsDeleted() bool {
	logger := s.logger.WithFields(logrus.Fields{"functionName": "WaitEndpointsDeleted"})
	// cilium-health endpoint is always running.
	desiredState := "1"
	body := func() bool {
		cmd := fmt.Sprintf(`cilium endpoint list -o json | jq '. | length'`)
		res := s.Exec(cmd)
		numEndpointsRunning := strings.TrimSpace(res.GetStdOut())
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

// WaitEndpointsReady waits up until timeout reached for all endpoints to not be
// in any regenerating or waiting-for-identity state. Returns true if all
// endpoints regenerate before HelperTimeout is exceeded, false otherwise.
func (s *SSHMeta) WaitEndpointsReady() bool {
	logger := s.logger.WithFields(logrus.Fields{"functionName": "WaitEndpointsReady"})
	desiredState := string(models.EndpointStateReady)
	body := func() bool {
		filter := `{range [*]}{@.container-name}{"="}{@.state}{"\n"}{end}`
		cmd := fmt.Sprintf(`cilium endpoint list -o jsonpath='%s'`, filter)

		res := s.Exec(cmd)
		values := res.KVOutput()
		total := len(values)

		result := map[string]int{}
		for _, status := range values {
			result[status]++
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
// configuration update command returned successfully and if the endpoint
// was able to regenerate successfully, false otherwise.
func (s *SSHMeta) EndpointSetConfig(id, option, value string) bool {
	// TODO: GH-1725.
	// For now use `grep` with an extra space to ensure that we only match
	// on specified option.
	// TODO: for consistency, all fields should be constants if they are reused.
	logger := s.logger.WithFields(logrus.Fields{"endpointID": id})
	res := s.ExecCilium(fmt.Sprintf(
		"endpoint config %s | grep '%s ' | awk '{print $2}'", id, option))

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

	return s.WaitEndpointRegenerated(id)
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
	filter := `{range [*]}{@.id}{"="}{@.container-name}{"\n"}{end}`
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
	// cilium endpoint list -o jsonpath='{range [?(@.labels.orchestration-identity[0]!='reserved:health')]}{@.container-name}{"="}{@.id}{"\n"}{end}'
	filter := `{range [?(@.labels.orchestration-identity[0]!="reserved:health")]}{@.container-name}{"="}{@.id}{"\n"}{end}`
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
	filter := `{range [*]}{@.container-name}{"="}{@.identity.id}{"\n"}{end}`
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
		return nil, fmt.Errorf("`cilium endpoint get` was not successful")
	}

	result, err := data.Filter("{ [?(@.labels.orchestration-identity[0]!='reserved:health')].container-name }")
	if err != nil {
		return nil, err
	}

	return strings.Split(result.String(), " "), nil
}

// ManifestsPath returns the path of the directory where manifests (YAMLs
// containing policies, DaemonSets, etc.) are stored for the runtime tests.
// TODO: this can just be a constant; there's no need to have a function.
func (s *SSHMeta) ManifestsPath() string {
	return fmt.Sprintf("%s/runtime/manifests/", BasePath)
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

	endpoints, err := res.Filter("{ [?(@.labels.orchestration-identity[0]!='reserved:health')].policy-enabled }")

	if err != nil {
		return result, fmt.Errorf(`cannot filter for "policy-enabled" from output of "cilium endpoint list"`)
	}
	status := strings.Split(endpoints.String(), " ")
	for _, kind := range status {
		switch kind {
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
	res := s.ExecCilium(fmt.Sprintf("config | grep %s | awk '{print $2}'", PolicyEnforcement))
	if res.SingleOut() == status {
		return res
	}
	return s.ExecCilium(fmt.Sprintf("config %s=%s", PolicyEnforcement, status))
}

// PolicyDelAll deletes all policy rules currently imported into Cilium.
func (s *SSHMeta) PolicyDelAll() *CmdRes {
	return s.PolicyDel("--all")
}

// PolicyDel deletes the policy with the given ID from Cilium.
func (s *SSHMeta) PolicyDel(id string) *CmdRes {
	res := s.ExecCilium(fmt.Sprintf(
		"policy delete %s | grep Revision: | awk '{print $2}'", id))
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
	//FIXME GH-1725
	rev := s.ExecCilium("policy get | grep Revision| awk '{print $2}'")
	return rev.IntOutput()
}

// PolicyImportAndWait imports a new policy into Cilium and waits until the policy
// revision number increments.
func (s *SSHMeta) PolicyImportAndWait(path string, timeout time.Duration) (int, error) {
	ginkgo.By(fmt.Sprintf("Setting up policy: %s", path))

	revision, err := s.PolicyGetRevision()
	if err != nil {
		return -1, fmt.Errorf("cannot get policy revision: %s", err)
	}
	s.logger.WithFields(logrus.Fields{
		logfields.Path:           path,
		logfields.PolicyRevision: revision}).Infof("before importing policy")
	res := s.ExecCilium(fmt.Sprintf("policy import %s", path))
	if res.WasSuccessful() == false {
		s.logger.WithFields(logrus.Fields{
			logfields.Path: path,
		}).Errorf("could not import policy: %s", res.CombineOutput())
		return -1, fmt.Errorf("could not import policy %s", path)
	}
	body := func() bool {
		currentRev, _ := s.PolicyGetRevision()
		if currentRev > revision {
			s.PolicyWait(currentRev)
			return true
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
	err := RenderTemplateToFile(filename, policy, os.ModePerm)
	if err != nil {
		s.logger.Errorf("PolicyRenderAndImport: cannot create policy file on '%s'", filename)
		return 0, fmt.Errorf("cannot render the policy:  %s", err)
	}
	path := GetFilePath(filename)
	s.logger.Debugf("PolicyRenderAndImport: import policy from '%s'", path)
	defer os.Remove(filename)
	return s.PolicyImportAndWait(path, HelperTimeout)
}

// PolicyWait executes `cilium policy wait`, which waits until all endpoints are
// updated to the given policy revision.
func (s *SSHMeta) PolicyWait(revisionNum int) *CmdRes {
	return s.ExecCilium(fmt.Sprintf("policy wait %d", revisionNum))
}

// ReportFailed gathers relevant Cilium runtime data and logs for debugging
// purposes.
func (s *SSHMeta) ReportFailed(commands ...string) {
	wr := s.logger.Logger.Out
	fmt.Fprint(wr, "===================== TEST FAILED =====================\n")
	fmt.Fprint(wr, "StackTrace Begin\n")

	//FIXME: Ginkgo PR383 add here --since option
	res := s.Exec("sudo journalctl --no-pager -u cilium | tail -n 50")
	fmt.Fprint(wr, res.Output())

	fmt.Fprint(wr, "\n")
	res = s.ExecCilium("endpoint list")
	fmt.Fprint(wr, res.Output())

	for _, cmd := range commands {
		fmt.Fprintf(wr, "\nOutput of command '%s': \n", cmd)
		res = s.Exec(fmt.Sprintf("%s", cmd))
		fmt.Fprint(wr, res.Output())
	}
	fmt.Fprint(wr, "StackTrace Ends\n")
	s.ReportDump()
	s.GatherLogs()
	fmt.Fprint(wr, "===================== EXITING REPORT GENERATION =====================\n")
}

// ReportDump runs a variety of commands and writes the results to
// testResultsPath
func (s *SSHMeta) ReportDump() {

	reportEndpointsCommands := map[string]string{
		"cilium endpoint get %s":        "endpoint_%s.txt",
		"sudo cilium bpf policy get %s": "bpf_policy_get_%s.txt",
	}

	testPath, err := ReportDirectory()
	if err != nil {
		s.logger.WithError(err).Errorf(
			"cannot create test results path '%s'", testPath)
		return
	}
	reportMap(testPath, ciliumCLICommands, s)

	// Endpoint specific information:
	eps, err := s.GetEndpointsIds()
	if err != nil {
		s.logger.Errorf("cannot get endpoint ids")
	}
	for _, ep := range eps {
		for cmd, logfile := range reportEndpointsCommands {
			command := fmt.Sprintf(cmd, ep)
			res := s.Exec(command)

			err = ioutil.WriteFile(
				fmt.Sprintf("%s/%s", testPath, fmt.Sprintf(logfile, ep)),
				res.CombineOutput().Bytes(),
				LogPerm)

			if err != nil {
				s.logger.WithError(err).Errorf("cannot create test results for '%s'", command)
			}
		}
	}

	eps, err = s.GetEndpointsIdentityIds()
	if err != nil {
		s.logger.WithError(err).Error("cannot get endpoint identity ids")
	}
	for _, ep := range eps {
		res := s.Exec(fmt.Sprintf("cilium identity get %s", ep))
		err = ioutil.WriteFile(
			fmt.Sprintf("%s/%s", testPath, fmt.Sprintf("identity_%s.txt", ep)),
			res.CombineOutput().Bytes(),
			LogPerm)
		if err != nil {
			s.logger.WithError(err).Errorf("cannot create test results for identity get")
		}
	}
}

// GatherLogs dumps Cilium, Cilium Docker, key-value store logs, and gops output
// to the directory testResultsPath
func (s *SSHMeta) GatherLogs() {
	ciliumLogCommands := map[string]string{
		fmt.Sprintf("sudo journalctl -xe -u %s --no-pager", DaemonName):            "cilium.log",
		fmt.Sprintf("sudo journalctl -xe -u %s--no-pager", CiliumDockerDaemonName): "cilium-docker.log",
		"sudo docker logs cilium-consul":                                           "consul.log",
		fmt.Sprintf(`sudo bash -c "gops memstats $(pgrep %s)"`, AgentDaemon):       "gops_memstats.txt",
		fmt.Sprintf(`sudo bash -c "gops stack $(pgrep %s)"`, AgentDaemon):          "gops_stack.txt",
		fmt.Sprintf(`sudo bash -c "gops stats $(pgrep %s)"`, AgentDaemon):          "gops_stats.txt",
	}

	testPath, err := ReportDirectory()
	if err != nil {
		s.logger.WithError(err).Errorf(
			"cannot create test results path '%s'", testPath)
		return
	}
	reportMap(testPath, ciliumLogCommands, s)

	ciliumBPFStateCommands := []string{
		fmt.Sprintf("sudo cp -r %s %s/%s/lib", RunDir, BasePath, testPath),
		fmt.Sprintf("sudo cp -r %s %s/%s/run", LibDir, BasePath, testPath),
	}

	for _, cmd := range ciliumBPFStateCommands {
		res := s.Exec(cmd)
		if !res.WasSuccessful() {
			s.logger.Errorf("cannot gather files for cmd '%s': %s", cmd, res.CombineOutput())
		}
	}
}

// ServiceAdd creates a new Cilium service with the provided ID, frontend,
// backends. Returns the result of creating said service.
func (s *SSHMeta) ServiceAdd(id int, frontend string, backends []string) *CmdRes {
	cmd := fmt.Sprintf(
		"service update --frontend '%s' --backends '%s' --id '%d' --rev",
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

	bpfLB, err := s.BpfLBList()
	if err != nil {
		return false, err
	}

	frontendAddr := net.JoinHostPort(
		svc.FrontendAddress.IP,
		fmt.Sprintf("%d", svc.FrontendAddress.Port))
	lb, ok := bpfLB[frontendAddr]
	if ok == false {
		return false, fmt.Errorf(
			"frontend address from the service %d does not have it's corresponding frontend address(%s) on bpf maps",
			id, frontendAddr)
	}

	for _, backendAddr := range svc.BackendAddresses {
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
		svc.FrontendAddress.IP,
		fmt.Sprintf("%d", svc.FrontendAddress.Port))
	return frontendAddress, nil
}

// ServiceGetIds returns an array with the IDs of all Cilium services. Returns
// an error if the IDs cannot be retrieved
func (s *SSHMeta) ServiceGetIds() ([]string, error) {
	filter := `{range [*]}{@.ID}{end}`
	res, err := s.ServiceList().Filter(filter)
	if err != nil {
		return nil, err
	}
	return strings.Split(res.String(), "\n"), nil
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
	template := `
PATH=/usr/lib/llvm-3.8/bin:/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/sbin:/sbin:/bin
CILIUM_OPTS=--kvstore consul --kvstore-opt consul.address=127.0.0.1:8500 --debug --debug-verbose flow
INITSYSTEM=SYSTEMD`

	err := RenderTemplateToFile("cilium", template, os.ModePerm)
	if err != nil {
		return err
	}
	defer os.Remove("cilium")

	res := s.Exec("sudo cp /vagrant/cilium /etc/sysconfig/cilium")
	if !res.WasSuccessful() {
		return fmt.Errorf("%s", res.CombineOutput())
	}
	res = s.Exec("sudo systemctl restart cilium")
	if !res.WasSuccessful() {
		return fmt.Errorf("%s", res.CombineOutput())
	}
	return nil
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
	ginkgo.By("Restarting Cilium")

	res := s.ExecWithSudo("systemctl restart cilium")
	if !res.WasSuccessful() {
		return fmt.Errorf("%s", res.CombineOutput())
	}
	if err := s.WaitUntilReady(100); err != nil {
		return err
	}
	if !s.WaitEndpointsReady() {
		return fmt.Errorf("Endpoints are not ready after timeout")
	}
	return nil
}
