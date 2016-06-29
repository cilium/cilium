package client

import (
	"encoding/json"
	"fmt"

	"github.com/noironetworks/cilium-net/common/types"
)

func processErrorBody(serverResp []byte, i interface{}) error {
	var sErr types.ServerError
	if err := json.Unmarshal(serverResp, &sErr); err != nil {
		return fmt.Errorf("error retrieving server body response: %s [%s]", err, string(serverResp))
	}
	return fmt.Errorf("server error for interface: (%T) \"%+v\", (%d) %s", i, i, sErr.Code, sErr.Text)
}
