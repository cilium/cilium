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
	"os"
	"strings"
	"time"

	"github.com/cilium/cilium/api/v1/models"

	log "github.com/sirupsen/logrus"
)

const (
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

	var data []models.Endpoint
	err := c.Exec(fmt.Sprintf("endpoint get %s", id)).UnMarshal(&data)
	if err != nil {
		c.logger.Errorf("EndpointGet fail %d: %s", id, err)
		return nil
	}
	if len(data) > 0 {
		return &data[0]
	}
	return nil
}

// EndpointSetConfig sets the provided configuration option to the provided
// value for the endpoint with the endpoint ID id.
func (c *Cilium) EndpointSetConfig(id, option, value string) bool {
	// TODO: GH-1725.
	// For now use `grep` with an extra space to ensure that we only match
	// on specified option.
	// TODO: for consistency, all fields should be constants if they are reused.
	logger := c.logger.WithFields(log.Fields{"EndpointId": id})
	res := c.Exec(fmt.Sprintf(
		"endpoint config %s | grep '%s ' | awk '{print $2}'", id, option))

	if res.SingleOut() == value {
		return res.WasSuccessful()
	}

	before := c.EndpointGet(id)
	if before == nil {
		return false
	}
	data := c.Exec(fmt.Sprintf("endpoint config %s %s=%s", id, option, value))
	if !data.WasSuccessful() {
		logger.Errorf("cannot set endpoint configuration %s=%s", option, value)
		return false
	}
	err := WithTimeout(func() bool {
		status := c.EndpointGet(id)
		if len(status.Status) > len(before.Status) {
			return true
		}
		logger.Info("endpoint not regenerated")
		return false
	}, "endpoint not regenerated", &TimeoutConfig{Timeout: 100})
	if err != nil {
		logger.Errorf("endpoint configuration update failed:%s", err)
		return false
	}
	return true
}

var EndpointWaitUntilReadyRetry int = 0 //List how many retries EndpointWaitUntilReady should have

// EndpointWaitUntilReady waits until all of the endpoints that Cilium manages
// are in 'ready' state.
func (c *Cilium) EndpointWaitUntilReady(validation ...bool) bool {

	logger := c.logger.WithFields(log.Fields{"EndpointWaitReady": ""})

	getEpsStatus := func(data []models.Endpoint) map[int64]int {
		result := make(map[int64]int)
		for _, v := range data {
			result[v.ID] = len(v.Status)
		}
		return result
	}

	var data []models.Endpoint

	if err := c.GetEndpoints().UnMarshal(&data); err != nil {
		if EndpointWaitUntilReadyRetry > MaxRetries {
			logger.Errorf("%d retries exceeded to get endpoints: %s", MaxRetries, err)
			return false
		}
		logger.Infof("cannot get endpoints: %s", err)
		logger.Infof("sleeping 5 seconds and trying again to get endpoints")
		EndpointWaitUntilReadyRetry++
		Sleep(5)
		return c.EndpointWaitUntilReady(validation...)
	}
	EndpointWaitUntilReadyRetry = 0 //Reset to 0
	epsStatus := getEpsStatus(data)

	body := func() bool {
		var data []models.Endpoint

		if err := c.GetEndpoints().UnMarshal(&data); err != nil {
			logger.Info("cannot get endpoints: %s", err)
			return false
		}
		var valid, invalid int
		for _, eps := range data {
			if eps.State != "ready" {
				invalid++
			} else {
				valid++
			}
			if len(validation) > 0 && validation[0] {
				// If the endpoint's latest statest message does not contain "Policy regeneration skipped", then it must be regenerating; wait until length of status message array changes.
				if originalVal, _ := epsStatus[eps.ID]; !(len(eps.Status) > 0 && eps.Status[0].Message == "Policy regeneration skipped") && len(eps.Status) <= originalVal {
					logger.Infof("endpoint %d not regenerated", eps.ID)
					return false
				}
			}
		}

		if invalid == 0 {
			return true
		}

		logger.WithFields(log.Fields{
			"valid":   valid,
			"invalid": invalid,
		}).Info("endpoints not ready")

		return false
	}
	err := WithTimeout(body, "endpoints not ready", &TimeoutConfig{Timeout: 300})
	if err != nil {
		return false
	}
	return true
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
		c.EndpointWaitUntilReady(true)
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
}

// ServiceAdd creates a new Cilium service with the provided ID, frontend,
// backends, and revNAT number. Returns the result of creating said service.
func (c *Cilium) ServiceAdd(id int, frontend string, backends []string, rev int) *CmdRes {
	cmd := fmt.Sprintf(
		"service update --frontend '%s' --backends '%s' --id '%d' --rev '%d'",
		frontend, strings.Join(backends, ","), id, rev)
	return c.Exec(cmd)
}

// ServiceGet is a wrapper around `cilium service get <id>`. It returns the
// result of retrieving said service.
func (c *Cilium) ServiceGet(id int) *CmdRes {
	return c.Exec(fmt.Sprintf("service get '%d'", id))
}

// ServiceDel is a wrapper around `cilium service delete <id>`. It returns the
// result of deleting said service.
func (c *Cilium) ServiceDel(id int) *CmdRes {
	return c.Exec(fmt.Sprintf("service delete '%d'", id))
}

// SetUp sets up Cilium as a systemd service with a hardcoded set of options. It
// returns an error if any of the operations needed to start Cilium fails.
func (c *Cilium) SetUp() error {
	template := `
PATH=/usr/lib/llvm-3.8/bin:/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/sbin:/sbin:/bin
CILIUM_OPTS=--kvstore consul --kvstore-opt consul.address=127.0.0.1:8500 --debug
INITSYSTEM=SYSTEMD`

	err := RenderTemplateToFile("cilium", template, 0777)
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
