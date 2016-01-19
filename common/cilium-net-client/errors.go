package cilium_net_client

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/noironetworks/cilium-net/common/types"
)

var ErrConnectionFailed = errors.New("Cannot connect to the cilium-net-daemon. Is the cilium-net-daemon running on this host?")

func processErrorBody(serverResp io.ReadCloser, ep *types.Endpoint) error {
	bytes, err := ioutil.ReadAll(serverResp)
	if err != nil {
		fmt.Errorf("error retrieving server body response: %s", err)
	}
	return fmt.Errorf("'%+v': %s", ep, string(bytes))
}
