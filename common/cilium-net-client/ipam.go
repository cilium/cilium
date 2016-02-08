package cilium_net_client

import (
	"fmt"
	"net/http"
	"net/url"
	"encoding/json"

	"github.com/noironetworks/cilium-net/common/types"

)

func (cli Client) AllocateIPs(containerID string) (*types.IPAMConfig, error) {
	query := url.Values{}

	serverResp, err := cli.put("/allocator/container/"+containerID, query, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("error while connecting to daemon: %s", err)
	}

	defer ensureReaderClosed(serverResp)

	if serverResp.statusCode != http.StatusCreated {
		return nil, processErrorBody(serverResp.body, nil)
	}

	jd := json.NewDecoder(serverResp.body)
	var newIPAMConfig types.IPAMConfig
	if err := jd.Decode(&newIPAMConfig); err != nil {
		return nil, err
	}

	return &newIPAMConfig, nil
}

func (cli Client) ReleaseIPs(containerID string) error {
	query := url.Values{}

	serverResp, err := cli.delete("/allocator/container/"+containerID, query, nil)
	if err != nil {
		return fmt.Errorf("error while connecting to daemon: %s", err)
	}

	defer ensureReaderClosed(serverResp)

	if serverResp.statusCode != http.StatusNoContent &&
		serverResp.statusCode != http.StatusNotFound {
		return processErrorBody(serverResp.body, nil)
	}

	return nil
}
