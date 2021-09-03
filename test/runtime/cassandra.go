// Copyright 2018-2019 Authors of Cilium
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

package RuntimeTest

import (
	"fmt"
	"time"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
	"github.com/cilium/cilium/test/helpers/constants"

	. "github.com/onsi/gomega"
)

var _ = Describe("RuntimeCassandra", func() {

	var (
		vm            *helpers.SSHMeta
		testStartTime time.Time
		cassandraIP   string
	)

	containers := func(mode string) {

		images := map[string]string{
			"cass-server": constants.CassandraImage,
			"cass-client": constants.CassandraImage,
		}
		cmds := map[string][]string{
			"cass-client": {"sleep", "10000"},
		}

		switch mode {
		case "create":
			for k, v := range images {
				cmd, ok := cmds[k]
				var res *helpers.CmdRes
				if ok {
					res = vm.ContainerCreate(k, v, helpers.CiliumDockerNetwork, fmt.Sprintf("-l id.%s", k), cmd...)
				} else {
					res = vm.ContainerCreate(k, v, helpers.CiliumDockerNetwork, fmt.Sprintf("-l id.%s", k))
				}
				res.ExpectSuccess("failed to create container %s", k)
			}
			cassServer, err := vm.ContainerInspectNet("cass-server")
			Expect(err).Should(BeNil(), "Could not get cass-server network info")
			cassandraIP = cassServer["IPv4"]

		case "delete":
			for k := range images {
				vm.ContainerRm(k)
			}
		}
	}

	runCqlsh := func(cmd string) *helpers.CmdRes {
		logger.Infof("Executing command '%s'", cmd)
		res := vm.ContainerExec("cass-client", fmt.Sprintf(
			`cqlsh %s --connect-timeout=200 -e "%s"`, cassandraIP, cmd))
		return res
	}

	setupPostsTable := func() {
		r := runCqlsh("CREATE KEYSPACE posts_db WITH REPLICATION = { 'class' : 'NetworkTopologyStrategy', 'datacenter1' : 2 };")
		r.ExpectSuccess("Unable to create keyspace 'posts_db'")

		r = runCqlsh("CREATE TABLE posts_db.posts (username varchar, creation timeuuid, content varchar, PRIMARY KEY ((username), creation));")
		r.ExpectSuccess("Unable to create 'posts' table")

		r = runCqlsh("INSERT INTO posts_db.posts (username, creation, content) values ('dan', now(), 'Cilium Rocks!');")
		r.ExpectSuccess("Unable to insert into 'posts' table")
	}

	// Waits for the server to be ready, by executing
	// a command repeatedly until it succeeds, or a timeout occurs
	waitForCassandraServer := func() error {
		body := func() bool {
			res := runCqlsh("SELECT * from system.local")
			return res.WasSuccessful()
		}
		err := helpers.WithTimeout(body, "Cassandra server not ready", &helpers.TimeoutConfig{Timeout: helpers.HelperTimeout})
		return err
	}

	BeforeAll(func() {
		vm = helpers.InitRuntimeHelper(helpers.Runtime, logger)

		ExpectCiliumReady(vm)

		containers("create")
		Expect(vm.WaitEndpointsReady()).Should(BeTrue(), "Endpoints are not ready after timeout")

		err := waitForCassandraServer()
		Expect(err).To(BeNil(), "Cassandra Server failed to come up")

		// create keyspace, table, and do one insert
		// with no policy in place
		setupPostsTable()
	})

	AfterEach(func() {
		vm.PolicyDelAll()
	})

	AfterAll(func() {
		containers("delete")
		vm.CloseSSHClient()
	})

	JustBeforeEach(func() {
		testStartTime = time.Now()
	})

	JustAfterEach(func() {
		vm.ValidateNoErrorsInLogs(time.Since(testStartTime))
	})

	AfterFailed(func() {
		vm.ReportFailed("cilium policy get")
	})

	SkipItIf(helpers.SkipRaceDetectorEnabled, "Tests policy allowing all actions", func() {
		_, err := vm.PolicyImportAndWait(vm.GetFullPath("Policies-cassandra-allow-all.json"), helpers.HelperTimeout)
		Expect(err).Should(BeNil(), "Failed to import policy")

		endPoints, err := vm.PolicyEndpointsSummary()
		Expect(err).Should(BeNil(), "Cannot get endpoint list")
		Expect(endPoints[helpers.Enabled]).To(Equal(1),
			"Check number of endpoints with policy enforcement enabled")
		Expect(endPoints[helpers.Disabled]).To(Equal(2),
			"Check number of endpoints with policy enforcement disabled")

		By("Inserting Value into Cassandra (no policy)")
		r := runCqlsh("INSERT INTO posts_db.posts (username, creation, content) values ('alice', now(), 'Hello');")
		r.ExpectSuccess("Unable to insert into 'posts_db.posts' table")

		By("Reading values from Cassandra (no policy)")
		r = runCqlsh("SELECT * FROM posts_db.posts;")
		r.ExpectSuccess("Unable to select from 'posts' table")
		r.ExpectContains("alice", "Did not get inserted data in select")
	})

	SkipItIf(helpers.SkipRaceDetectorEnabled, "Tests policy disallowing Insert action", func() {

		_, err := vm.PolicyImportAndWait(vm.GetFullPath("Policies-cassandra-no-insert-posts.json"), helpers.HelperTimeout)
		Expect(err).Should(BeNil(), "Failed to import policy")

		endPoints, err := vm.PolicyEndpointsSummary()
		Expect(err).Should(BeNil(), "Cannot get endpoint list")
		Expect(endPoints[helpers.Enabled]).To(Equal(1),
			"Check number of endpoints with policy enforcement enabled")
		Expect(endPoints[helpers.Disabled]).To(Equal(2),
			"Check number of endpoints with policy enforcement disabled")

		By("Inserting Value into Cassandra (denied by policy)")
		r := runCqlsh("INSERT INTO posts_db.posts (username, creation, content) values ('bob', now(), 'Goodbye');")
		r.ExpectFail("Able to insert into 'posts_db.posts' table, which should be denied by policy")

		By("Reading values from Cassandra (allowed by policy)")
		r = runCqlsh("SELECT * FROM posts_db.posts;")
		r.ExpectSuccess("Unable to select from 'posts' table")
		r.ExpectContains("alice", "Did not get inserted data in select")
		r.ExpectDoesNotContain("bob", "Got value on select that should not have been inserted")
	})
})
