package metadata

import (
	"encoding/json"
	"fmt"
)

func GetContainerCgroupPath(containerID string) (string, error) {
	var cgroupPath string

	// The required container metadata is available with verbose mode.
	response, err := remoteRuntimeClient.ContainerStatus(containerID, true)
	if err != nil {
		return cgroupPath, fmt.Errorf("containerStatus call failed: %w", err)
	}

	var containerInfo map[string]string
	if containerInfo = response.GetInfo(); containerInfo == nil {
		return cgroupPath, fmt.Errorf("no info for ContainerResponse: (%s)", response)
	}

	cgroupPath, err = parseInfo(containerInfo)
	if err != nil {
		return cgroupPath, fmt.Errorf("failed to parse container info: %+v", containerInfo)
	}
	log.Infof("aditi-json (%s)", cgroupPath)

	return cgroupPath, nil
}

func parseInfo(info map[string]string) (string, error) {
	var (
		unmarshalledJson map[string]interface{}
		infoValJson      string
		infoKey          = "info"
		pathTraverse     = []string{"runtimeSpec", "linux", "cgroupsPath"}
		ok               bool
		err              error
	)

	if infoValJson, ok = info[infoKey]; !ok {
		return "", fmt.Errorf("no info found: %+v", info)
	}

	err = json.Unmarshal([]byte(infoValJson), &unmarshalledJson)
	if err != nil {
		return "", err
	}

	cgroupsPath := getStringAtJsonPath(unmarshalledJson, pathTraverse)

	return cgroupsPath, nil
}

func getStringAtJsonPath(jsonMap map[string]interface{}, path []string) string {
	jsonObj := jsonMap
	pathLen := len(path) - 1

	for _, elem := range path[:pathLen] {
		jsonObj = jsonObj[elem].(map[string]interface{})
	}

	return jsonObj[path[pathLen]].(string)
}
