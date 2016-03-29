package cilium_net_client

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"

	"github.com/noironetworks/cilium-net/common/types"
)

func (cli Client) PutLabels(labels types.Labels) (*types.SecCtxLabels, bool, error) {
	query := url.Values{}
	serverResp, err := cli.post("/labels", query, labels, nil)
	if err != nil {
		return nil, false, fmt.Errorf("error while connecting to daemon: %s", err)
	}

	defer ensureReaderClosed(serverResp)

	if serverResp.statusCode != http.StatusAccepted {
		return nil, false, processErrorBody(serverResp.body, nil)
	}

	var labelsResp types.SecCtxLabels
	if err := json.NewDecoder(serverResp.body).Decode(&labelsResp); err != nil {
		return nil, false, err
	}

	return &labelsResp, false, nil
}

func (cli Client) GetLabels(id int) (*types.SecCtxLabels, error) {
	query := url.Values{}

	serverResp, err := cli.get("/labels/by-uuid/"+strconv.Itoa(id), query, nil)
	if err != nil {
		return nil, fmt.Errorf("error while connecting to daemon: %s", err)
	}

	defer ensureReaderClosed(serverResp)

	if serverResp.statusCode != http.StatusNoContent &&
		serverResp.statusCode != http.StatusOK {
		return nil, processErrorBody(serverResp.body, nil)
	}

	if serverResp.statusCode == http.StatusNoContent {
		return nil, nil
	}

	b, err := ioutil.ReadAll(serverResp.body)

	log.Debugf("body %+v %+v", string(b), err)

	var labels types.SecCtxLabels
	if err := json.Unmarshal(b, &labels); err != nil {
		return nil, err
	}

	return &labels, nil
}

func (cli Client) GetMaxID() (int, error) {
	query := url.Values{}

	serverResp, err := cli.get("/labels/status/maxUUID", query, nil)
	if err != nil {
		return -1, fmt.Errorf("error while connecting to daemon: %s", err)
	}

	defer ensureReaderClosed(serverResp)

	if serverResp.statusCode != http.StatusOK {
		return -1, processErrorBody(serverResp.body, nil)
	}

	var maxID int
	if err := json.NewDecoder(serverResp.body).Decode(&maxID); err != nil {
		return -1, err
	}

	return maxID, nil
}
