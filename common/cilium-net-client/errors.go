package cilium_net_client

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/noironetworks/cilium-net/common/types"
)

var ErrConnectionFailed = errors.New("Cannot connect to the cilium-net-daemon. Is the cilium-net-daemon running on this host?")

func processErrorBody(serverResp io.ReadCloser, i interface{}) error {
	d := json.NewDecoder(serverResp)
	var sErr types.ServerError
	if err := d.Decode(&sErr); err != nil {
		fmt.Errorf("error retrieving server body response: %s", err)
	}
	return fmt.Errorf("server error for interface: (%T) \"%+v\", (%d) %s", i, i, sErr.Code, sErr.Text)
}
