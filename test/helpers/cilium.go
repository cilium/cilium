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
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common"

	"github.com/sirupsen/logrus"
)

var log = common.DefaultLogger

const (
	// MaxRetries is the number of times that a loop should iterate until a
	// specified condition is not met
	MaxRetries = 30
)

// Cilium is utilized to run cilium-specific commands on its SSHMeta. Informational
// output about the result of commands and the state of the node is stored in its
// associated logger.
type Cilium struct {
	Node *SSHMeta

	logger *log.Entry
}

// CreateCilium returns a Cilium object containing the SSHMeta of the provided vmName,
// as well as the provided logger.
func CreateCilium(vmName string, log *log.Entry) *Cilium {
	log.Infof("Cilium: set vmName to '%s'", vmName)
	node := GetVagrantSSHMetadata(vmName)
	if node == nil {
		return nil
	}

	return &Cilium{
		Node:   node,
		logger: log,
	}
}

// BpfLBList returns the output of `cilium bpf lb list -o json` as a map
// Key will be the frontend address and the value is an array with all backend
// addresses
func (c *Cilium) BpfLBList() (map[string][]string, error) {
	var result map[string][]string

	res := c.Exec("bpf lb list -o json")
	if !res.WasSuccessful() {
		return nil, fmt.Errorf("cannot get bpf lb list: %s", res.CombineOutput())
	}
	err := res.Unmarshal(&result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Exec runs a Cilium CLI command and returns the resultant cmdRes.
func (c *Cilium) Exec(cmd string) *CmdRes {
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	command := fmt.Sprintf("cilium %s", cmd)
	exit := c.Node.ExecWithSudo(command, stdout, stderr)
	return &CmdRes{
		cmd:    command,
		stdout: stdout,
		stderr: stderr,
		exit:   exit,
	}
}

// EndpointGet returns the output of `cilium endpoint get` for the provided
// endpoint ID.
func (c *Cilium) EndpointGet(id string) *models.Endpoint {
	if id == "" {
		return nil
	}
	var data []models.Endpoint
	endpointGetCmd := fmt.Sprintf("endpoint get %s", id)
	res := c.Exec(endpointGetCmd)
	err := res.Unmarshal(&data)
	if err != nil {
		c.logger.WithError(err).Errorf("EndpointGet fail %d", id)
		return nil
	}
	if len(data) > 0 {
		return &data[0]
	}
	return nil
}

// EndpointStatusLog returns the status log API model for the specified endpoint.
// Returns nil if no endpoint corresponds to the provided ID.
func (c *Cilium) EndpointStatusLog(id string) *models.EndpointStatusLog {
	if id == "" {
		return nil
	}

	var epStatusLog models.EndpointStatusLog

	endpointLogCmd := fmt.Sprintf("endpoint log %s", id)
	res := c.Exec(endpointLogCmd)
	err := res.Unmarshal(&epStatusLog)
	if err != nil {
		c.logger.WithFields(logrus.Fields{"endpointID": id}).WithError(err).Errorf("unable to get endpoint status log")
		return nil
	}

	return &epStatusLog
}

// WaitEndpointRegenerated attempts up until MaxRetries are exceeded for the
// endpoint with the specified ID to be in "ready" state. Returns false if
// no such endpoint corresponds to the given id or if MaxRetries are exceeded.
func (c *Cilium) WaitEndpointRegenerated(id string) bool {
	logger := c.logger.WithFields(logrus.Fields{
		"functionName": "WaitEndpointRegenerated",
		"id":           id,
	})

	counter := 0
	desiredState := models.EndpointStateReady

	endpoint := c.EndpointGet(id)
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

		endpoint = c.EndpointGet(id)
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

// WaitEndpointsReady waits up until MaxRetries times for all endpoints to
// not be in any regenerating or waiting-to-generate state. Returns true if
// all endpoints regenerate before MaxRetries are exceeded, false otherwise.
func (c *Cilium) WaitEndpointsReady() bool {
	logger := c.logger.WithFields(logrus.Fields{"functionName": "WaitEndpointsReady"})

	numDesired := 0
	counter := 0

	cmdString := "cilium endpoint list | grep -c regenerat"
	infoCmd := "cilium endpoint list"
	res := c.Node.Exec(cmdString)
	logger.Infof("string output of cmd: %s", res.stdout.String())
	numEndpointsRegenerating, err := strconv.Atoi(strings.TrimSuffix(res.stdout.String(), "\n"))

	// If the command error'd out for whatever reason, do not want numEndpointsRegenerating
	// to be set to zero. Handle this error and set to -1 so that the loop below
	// continues to execute up until MaxRetries are exceeded.
	if err != nil {
		numEndpointsRegenerating = -1
	}
	for numDesired != numEndpointsRegenerating {

		logger.WithFields(logrus.Fields{
			"regenerating": numEndpointsRegenerating,
		}).Info("endpoints are still regenerating")

		if counter > MaxRetries {
			logger.Infof("%d retries have been exceeded for waiting for endpoint regeneration", MaxRetries)
			return false
		}

		res := c.Node.Exec(infoCmd)
		logger.Infof("still within retry limit for waiting for endpoints to be in \"ready\" state; sleeping and checking again")
		Sleep(1)
		res = c.Node.Exec(cmdString)
		numEndpointsRegenerating, err = strconv.Atoi(strings.TrimSuffix(res.stdout.String(), "\n"))
		if err != nil {
			numEndpointsRegenerating = -1
		}
		counter++
	}

	return true
}

// EndpointSetConfig sets the provided configuration option to the provided
// value for the endpoint with the endpoint ID id. It returns true if the
// configuration update command returned successfully and if the endpoint
// was able to regenerate successfully, false otherwise.
func (c *Cilium) EndpointSetConfig(id, option, value string) bool {
	// TODO: GH-1725.
	// For now use `grep` with an extra space to ensure that we only match
	// on specified option.
	// TODO: for consistency, all fields should be constants if they are reused.
	logger := c.logger.WithFields(logrus.Fields{"endpointID": id})
	res := c.Exec(fmt.Sprintf(
		"endpoint config %s | grep '%s ' | awk '{print $2}'", id, option))

	if res.SingleOut() == value {
		logger.Debugf("no need to update %s=%s; value already set", option, value)
		return res.WasSuccessful()
	}

	configCmd := fmt.Sprintf("endpoint config %s %s=%s", id, option, value)
	data := c.Exec(configCmd)
	if !data.WasSuccessful() {
		logger.Errorf("cannot set endpoint configuration %s=%s", option, value)
		return false
	}

	return c.WaitEndpointRegenerated(id)
}

// GetEndpoints returns the CmdRes resulting from executing
// `cilium endpoint list -o json`.
func (c *Cilium) GetEndpoints() *CmdRes {
	return c.Exec("endpoint list -o json")
}

// GetEndpointsIds returns a mapping of a Docker container name to to its
// corresponding endpoint ID, and an error if the list of endpoints cannot be
// retrieved via the Cilium CLI.
func (c *Cilium) GetEndpointsIds() (map[string]string, error) {
	// cilium endpoint list -o jsonpath='{range [*]}{@.container-name}{"="}{@.id}{"\n"}{end}'
	filter := `{range [*]}{@.container-name}{"="}{@.id}{"\n"}{end}`
	cmd := fmt.Sprintf("endpoint list -o jsonpath='%s'", filter)
	endpoints := c.Exec(cmd)
	if !endpoints.WasSuccessful() {
		return nil, fmt.Errorf("%q failed: %s", cmd, endpoints.CombineOutput())
	}
	return endpoints.KVOutput(), nil
}

// GetEndpointsIdentityIds returns a mapping of a Docker container name to it's
// corresponding endpoint's security identity, it will return an error if the list
// of endpoints cannot be retrieved via the Cilium CLI.
func (c *Cilium) GetEndpointsIdentityIds() (map[string]string, error) {
	filter := `{range [*]}{@.container-name}{"="}{@.identity.id}{"\n"}{end}`
	endpoints := c.Exec(fmt.Sprintf("endpoint list -o jsonpath='%s'", filter))
	if !endpoints.WasSuccessful() {
		return nil, fmt.Errorf("cannot get endpoint list: %s", endpoints.CombineOutput())
	}
	return endpoints.KVOutput(), nil
}

// GetEndpointsNames returns the container-name field of each Cilium endpoint.
func (c *Cilium) GetEndpointsNames() ([]string, error) {
	data := c.GetEndpoints()
	if data.WasSuccessful() == false {
		return nil, fmt.Errorf("`cilium endpoint get` was not successful")
	}
	result, err := data.Filter("{ [*].container-name }")
	if err != nil {
		return nil, err
	}

	return strings.Split(result.String(), " "), nil
}

// ManifestsPath returns the path of the directory where manifests (YAMLs
// containing policies, DaemonSets, etc.) are stored for the runtime tests.
// TODO: this can just be a constant; there's no need to have a function.
func (c *Cilium) ManifestsPath() string {
	return fmt.Sprintf("%s/runtime/manifests/", BasePath)
}

// GetFullPath returns the path of file name prepended with the absolute path
// where manifests (YAMLs containing policies, DaemonSets, etc.) are stored.
func (c *Cilium) GetFullPath(name string) string {
	return fmt.Sprintf("%s%s", c.ManifestsPath(), name)
}

// PolicyEndpointsSummary returns the count of whether policy enforcement is
// enabled, disabled, and the total number of endpoints, and an error if the
// Cilium endpoint metadata cannot be retrieved via the API.
func (c *Cilium) PolicyEndpointsSummary() (map[string]int, error) {
	result := map[string]int{
		Enabled:  0,
		Disabled: 0,
		Total:    0,
	}

	endpoints, err := c.GetEndpoints().Filter("{ [*].policy-enabled }")
	if err != nil {
		return result, fmt.Errorf("cannot get endpoints")
	}
	status := strings.Split(endpoints.String(), " ")
	result[Enabled], result[Total] = CountValues("true", status)
	result[Disabled], result[Total] = CountValues("false", status)
	return result, nil
}

// SetPolicyEnforcement sets the PolicyEnforcement configuration value for the
// Cilium agent to the provided status.
func (c *Cilium) SetPolicyEnforcement(status string, waitReady ...bool) *CmdRes {
	// We check before setting PolicyEnforcement; if we do not, EndpointWait
	// will fail due to the status of the endpoints not changing.
	log.Infof("setting PolicyEnforcement=%s", status)
	res := c.Exec(fmt.Sprintf("config | grep %s | awk '{print $2}'", PolicyEnforcement))
	if res.SingleOut() == status {
		return res
	}
	res = c.Exec(fmt.Sprintf("config %s=%s", PolicyEnforcement, status))
	if len(waitReady) > 0 && waitReady[0] {
		c.WaitEndpointsReady()
	}
	return res
}

// PolicyDelAll deletes all policy rules currently imported into Cilium.
func (c *Cilium) PolicyDelAll() *CmdRes {
	return c.PolicyDel("--all")
}

// PolicyDel deletes the policy with the given ID from Cilium.
func (c *Cilium) PolicyDel(id string) *CmdRes {
	return c.Exec(fmt.Sprintf("policy delete %s", id))
}

// PolicyGet runs `cilium policy get <id>`, where id is the name of a specific
// policy imported into Cilium. It returns the resultant CmdRes from running
// the aforementioned command.
func (c *Cilium) PolicyGet(id string) *CmdRes {
	return c.Exec(fmt.Sprintf("policy get %s", id))
}

// PolicyGetAll gets all policies that are imported in the Cilium agent.
func (c *Cilium) PolicyGetAll() *CmdRes {
	return c.Exec("policy get")

}

// PolicyGetRevision retrieves the current policy revision number in the Cilium
// agent.
func (c *Cilium) PolicyGetRevision() (int, error) {
	//FIXME GH-1725
	rev := c.Exec("policy get | grep Revision| awk '{print $2}'")
	return rev.IntOutput()
}

// PolicyImport imports a new policy into Cilium and waits until the policy
// revision number increments.
func (c *Cilium) PolicyImport(path string, timeout time.Duration) (int, error) {
	revision, err := c.PolicyGetRevision()
	if err != nil {
		return -1, fmt.Errorf("cannot get policy revision: %s", err)
	}
	c.logger.Infof("PolicyImport: %s and current policy revision is '%d'", path, revision)
	res := c.Exec(fmt.Sprintf("policy import %s", path))
	if res.WasSuccessful() == false {
		c.logger.Errorf("could not import policy: %s", res.CombineOutput())
		return -1, fmt.Errorf("could not import policy %s", path)
	}
	body := func() bool {
		currentRev, _ := c.PolicyGetRevision()
		if currentRev > revision {
			c.PolicyWait(currentRev)
			return true
		}
		c.logger.Infof("PolicyImport: current revision %d same as %d", currentRev, revision)
		return false
	}
	err = WithTimeout(body, "could not import policy revision", &TimeoutConfig{Timeout: timeout})
	if err != nil {
		return -1, err
	}
	revision, err = c.PolicyGetRevision()
	c.logger.Infof("PolicyImport: finished %q with revision '%d'", path, revision)
	return revision, err
}

// PolicyWait executes `cilium policy wait`, which waits until all endpoints are
// updated to the given policy revision.
func (c *Cilium) PolicyWait(revisionNum int) *CmdRes {
	return c.Exec(fmt.Sprintf("policy wait %d", revisionNum))
}

// ReportFailed gathers relevant Cilium runtime data and logs for debugging
// purposes.
func (c *Cilium) ReportFailed(commands ...string) {
	wr := c.logger.Logger.Out
	fmt.Fprint(wr, "StackTrace Begin\n")

	//FIXME: Ginkgo PR383 add here --since option
	res := c.Node.Exec("sudo journalctl --no-pager -u cilium")
	fmt.Fprint(wr, res.Output())

	fmt.Fprint(wr, "\n")
	res = c.Exec("endpoint list")
	fmt.Fprint(wr, res.Output())

	for _, cmd := range commands {
		fmt.Fprintf(wr, "\nOutput of command '%s': \n", cmd)
		res = c.Node.Exec(fmt.Sprintf("%s", cmd))
		fmt.Fprint(wr, res.Output())
	}
	fmt.Fprint(wr, "StackTrace Ends\n")
	c.ReportDump()
	c.GatherLogs()
}

// ReportDump runs a variety of commands and writes the results to
// testResultsPath
func (c *Cilium) ReportDump() {

	reportEndpointsCommands := map[string]string{
		"cilium endpoint get %s":         "endpoint_%s.txt",
		"sudo cilium bpf policy list %s": "bpf_policy_list_%s.txt",
	}

	testPath, err := ReportDirectory()
	if err != nil {
		c.logger.WithError(err).Errorf(
			"cannot create test results path '%s'", testPath)
		return
	}
	reportMap(testPath, ciliumCLICommands, c.Node)

	// Endpoint specific information:
	eps, err := c.GetEndpointsIds()
	if err != nil {
		c.logger.Errorf("cannot get endpoint ids")
	}
	for _, ep := range eps {
		for cmd, logfile := range reportEndpointsCommands {
			command := fmt.Sprintf(cmd, ep)
			res := c.Node.Exec(command)

			err = ioutil.WriteFile(
				fmt.Sprintf("%s/%s", testPath, fmt.Sprintf(logfile, ep)),
				res.CombineOutput().Bytes(),
				os.ModePerm)

			if err != nil {
				c.logger.WithError(err).Errorf("cannot create test results for '%s'", command)
			}
		}
	}

	eps, err = c.GetEndpointsIdentityIds()
	if err != nil {
		c.logger.WithError(err).Error("cannot get endpoint identity ids")
	}
	for _, ep := range eps {
		res := c.Node.Exec(fmt.Sprintf("cilium identity get %s", ep))
		err = ioutil.WriteFile(
			fmt.Sprintf("%s/%s", testPath, fmt.Sprintf("identity_%s.txt", ep)),
			res.CombineOutput().Bytes(),
			os.ModePerm)
		if err != nil {
			c.logger.WithError(err).Errorf("cannot create test results for identity get")
		}
	}
}

// GatherLogs dumps Cilium, Cilium Docker, key-value store logs, and gops output
// to the directory testResultsPath
func (c *Cilium) GatherLogs() {
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
		c.logger.WithError(err).Errorf(
			"cannot create test results path '%s'", testPath)
		return
	}
	reportMap(testPath, ciliumLogCommands, c.Node)

	ciliumBPFStateCommands := []string{
		fmt.Sprintf("sudo cp -r %s %s/%s/lib", RunDir, BasePath, testPath),
		fmt.Sprintf("sudo cp -r %s %s/%s/run", LibDir, BasePath, testPath),
	}

	for _, cmd := range ciliumBPFStateCommands {
		res := c.Node.Exec(cmd)
		if !res.WasSuccessful() {
			c.logger.Errorf("cannot gather files for cmd '%s': %s", cmd, res.CombineOutput())
		}
	}
}

// ServiceAdd creates a new Cilium service with the provided ID, frontend,
// backends, and revNAT number. Returns the result of creating said service.
func (c *Cilium) ServiceAdd(id int, frontend string, backends []string, rev int) *CmdRes {
	cmd := fmt.Sprintf(
		"service update --frontend '%s' --backends '%s' --id '%d' --rev '%d'",
		frontend, strings.Join(backends, ","), id, rev)
	return c.Exec(cmd)
}

// ServiceDel is a wrapper around `cilium service delete <id>`. It returns the
// result of deleting said service.
func (c *Cilium) ServiceDel(id int) *CmdRes {
	return c.Exec(fmt.Sprintf("service delete '%d'", id))
}

// ServiceIsSynced checks that the Cilium service with the specified id has its
// metadata match that of the load balancer BPF maps
func (c *Cilium) ServiceIsSynced(id int) (bool, error) {
	var svc *models.Service
	svcRes := c.ServiceGet(id)
	if !svcRes.WasSuccessful() {
		return false, fmt.Errorf("cannot get service id %d: %s", id, svcRes.CombineOutput())
	}
	err := svcRes.Unmarshal(&svc)
	if err != nil {
		return false, err
	}

	bpfLB, err := c.BpfLBList()
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
func (c *Cilium) ServiceList() *CmdRes {
	return c.Exec("service list -o json")
}

// ServiceGet is a wrapper around `cilium service get <id>`. It returns the
// result of retrieving said service.
func (c *Cilium) ServiceGet(id int) *CmdRes {
	return c.Exec(fmt.Sprintf("service get '%d' -o json", id))
}

// ServiceGetFrontendAddress returns a string with the frontend address and
// port. It returns an error if the ID cannot be retrieved.
func (c *Cilium) ServiceGetFrontendAddress(id int) (string, error) {

	var svc *models.Service
	res := c.ServiceGet(id)
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
func (c *Cilium) ServiceGetIds() ([]string, error) {
	filter := `{range [*]}{@.ID}{end}`
	res, err := c.ServiceList().Filter(filter)
	if err != nil {
		return nil, err
	}
	return strings.Split(res.String(), "\n"), nil
}

// SetUp sets up Cilium as a systemd service with a hardcoded set of options. It
// returns an error if any of the operations needed to start Cilium fails.
func (c *Cilium) SetUp() error {
	template := `
PATH=/usr/lib/llvm-3.8/bin:/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/sbin:/sbin:/bin
CILIUM_OPTS=--kvstore consul --kvstore-opt consul.address=127.0.0.1:8500 --debug
INITSYSTEM=SYSTEMD`

	err := RenderTemplateToFile("cilium", template, os.ModePerm)
	if err != nil {
		return err
	}
	defer os.Remove("cilium")

	res := c.Node.Exec("sudo cp /vagrant/cilium /etc/sysconfig/cilium")
	if !res.WasSuccessful() {
		return fmt.Errorf("%s", res.CombineOutput())
	}
	res = c.Node.Exec("sudo systemctl restart cilium")
	if !res.WasSuccessful() {
		return fmt.Errorf("%s", res.CombineOutput())
	}
	return nil
}

// WaitUntilReady waits until the output of `cilium status` returns with code
// zero. Returns an error if the output of `cilium status` returns a nonzero
// return code after the specified timeout duration has elapsed.
func (c *Cilium) WaitUntilReady(timeout time.Duration) error {

	body := func() bool {
		res := c.Exec("status")
		c.logger.Infof("Cilium status is %t", res.WasSuccessful())
		return res.WasSuccessful()
	}
	err := WithTimeout(body, "Cilium is not ready", &TimeoutConfig{Timeout: timeout})
	return err
}
