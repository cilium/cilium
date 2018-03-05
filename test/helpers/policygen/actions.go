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
package policygen

import (
	"fmt"
	"net/http"

	"github.com/cilium/cilium/test/helpers"

	log "github.com/sirupsen/logrus"
)

// HTTPAction runs a helpers.CurlFail from specified pod to a specified target.
// It needs a `helpers.Kubectl` instance to run the command in the pod. It
// returns a ResultType struct.
func HTTPAction(srcPod string, target string, kub *helpers.Kubectl) ResultType {
	command := fmt.Sprintf(
		"%s exec -n %s %s 2>/dev/null -- %s --output /dev/stout -w '%%{http_code}'",
		helpers.KubectlCmd, helpers.DefaultNamespace,
		srcPod, helpers.CurlFail(target))

	log.Infof("Executing HTTPAction '%s'", command)
	res := kub.Exec(command)
	if res.WasSuccessful() {
		return ResultOK
	}
	// Curl exitcodes are described in https://curl.haxx.se/libcurl/c/libcurl-errors.html
	switch exitCode := res.GetExitCode(); exitCode {
	case 28: //CURLE_OPERATION_TIMEDOUT (28)
		return ResultTimeout
	case 22: //CURLE_HTTP_RETURNED_ERROR
		val, err := res.IntOutput()
		if err != nil {
			return ResultAuth
		}
		if val == http.StatusServiceUnavailable {
			// This is for case  "L3:No Policy L4:Ingress Port 80 UDP L7:Egress
			// policy to /private/" where the cilium egress proxy cannot connect
			// to endpoint due timeout and return back a 503.
			return ResultTimeout
		}
		return ResultAuth
	default:
		log.Infof("HTTPAction returned unexpected exit code %d", exitCode)
	}
	return ResultOK
}

// HTTPActionPrivate runs a HTTPAction to /private/ using destTargetDetails
func HTTPActionPrivate(srcPod string, dest TargetDetails, kub *helpers.Kubectl) ResultType {
	return HTTPAction(
		srcPod,
		fmt.Sprintf("http://%s/private", dest),
		kub)
}

// HTTPActionPublic runs a CurlAction to /public/ using destTargetDetails
func HTTPActionPublic(srcPod string, dest TargetDetails, kub *helpers.Kubectl) ResultType {
	return HTTPAction(
		srcPod,
		fmt.Sprintf("http://%s/public", dest),
		kub)
}

// NetPerfAction TODO make this function (GH-2029)
func NetPerfAction(srcPod string, dest TargetDetails, kub *helpers.Kubectl) ResultType {
	return ResultType{}
}

// PingAction executes a ping from the `srcPod` to the dest using Kubectl
// object. Returns a ResultType corresponding to the exit code of the ping
// command.
func PingAction(srcPod string, dest TargetDetails, kub *helpers.Kubectl) ResultType {
	command := fmt.Sprintf("%s exec -n %s %s -- %s",
		helpers.KubectlCmd, helpers.DefaultNamespace,
		srcPod, helpers.Ping(string(dest.IP)))

	res := kub.Exec(command)
	if res.WasSuccessful() {
		return ResultOK
	}
	return ResultTimeout
}
