package cilium_net_client

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/noironetworks/cilium-net/common/types"
)

func (cli Client) GetLabelsID(labels types.Labels) (int, error) {
	query := url.Values{}
	serverResp, err := cli.post("/labels", query, labels, nil)
	if err != nil {
		return -1, fmt.Errorf("error while connecting to daemon: %s", err)
	}

	defer ensureReaderClosed(serverResp)

	if serverResp.statusCode != http.StatusAccepted {
		return -1, processErrorBody(serverResp.body, nil)
	}

	jd := json.NewDecoder(serverResp.body)
	var labelsResp types.LabelsResponse
	if err := jd.Decode(&labelsResp); err != nil {
		return -1, err
	}

	return labelsResp.ID, nil
}

func (cli Client) GetLabels(id int) (*types.Labels, error) {
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

	jd := json.NewDecoder(serverResp.body)
	var labels types.Labels
	if err := jd.Decode(&labels); err != nil {
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

	jd := json.NewDecoder(serverResp.body)
	var lblResponse types.LabelsResponse
	if err := jd.Decode(&lblResponse); err != nil {
		return -1, err
	}

	return lblResponse.ID, nil
}
