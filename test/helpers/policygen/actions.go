package policygen

import (
	"fmt"

	"github.com/cilium/cilium/test/helpers"
	log "github.com/sirupsen/logrus"
)

// HTTPAction runs a helpers.CurlFail from specified pod to a specified target.
// It needs a `helpers.Kubectl` instance to run the comamnd in the pod. It
// returns a ResultType struct.
func HTTPAction(srcPod string, target string, kub *helpers.Kubectl) *ResultType {
	command := fmt.Sprintf("%s exec -n %s %s -- %s",
		"kubectl", helpers.DefaultNamespace,
		srcPod, helpers.CurlFail(target))

	log.Infof("Executing HTTPAction '%s'", command)
	res := kub.Exec(command)
	if res.WasSuccessful() {
		return &ResultOK
	}
	// Curl exitcodes are described in https://curl.haxx.se/libcurl/c/libcurl-errors.html
	switch exitCode := res.GetExitCode(); exitCode {
	case 28: //CURLE_OPERATION_TIMEDOUT (28)
		return &ResultTimeout
	case 22: //CURLE_HTTP_RETURNED_ERROR
		return &ResultAuth
	default:
		log.Infof("HTTPAction returns exitcode '%d' and it's not handle", exitCode)
		return &ResultOK
	}
	return nil
}

// HTTPActionPrivate runs a CurlAction to private http target using destTargetDetails
func HTTPActionPrivate(srcPod string, dest *TargetDetails, kub *helpers.Kubectl) *ResultType {
	return HTTPAction(
		srcPod,
		fmt.Sprintf("http://%s/private", dest),
		kub)
}

// HTTPActionPublic runs a CurlAction to public http target using destTargetDetails
func HTTPActionPublic(srcPod string, dest *TargetDetails, kub *helpers.Kubectl) *ResultType {
	return HTTPAction(
		srcPod,
		fmt.Sprintf("http://%s/public", dest),
		kub)
}

// NetPerfAction TODO make this function
func NetPerfAction(srcPod string, dest *TargetDetails, kub *helpers.Kubectl) *ResultType {
	return nil
}

// PingAction executes a ping from the `srcPod` to the destination Target using
// Kubectl object. It will return a ResultType based on the exitCode
func PingAction(srcPod string, dest *TargetDetails, kub *helpers.Kubectl) *ResultType {
	command := fmt.Sprintf("%s exec -n %s %s -- %s",
		"kubectl", helpers.DefaultNamespace,
		srcPod, helpers.Ping(dest.IP))

	res := kub.Exec(command)
	if res.WasSuccessful() {
		return &ResultOK
	}
	return &ResultTimeout
}
