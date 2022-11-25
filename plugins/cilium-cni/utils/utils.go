package utils

import (
	"fmt"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/client"
)

func GetConfigFromCiliumAgent(client *client.Client) (*models.DaemonConfigurationStatus, error) {
	configResult, err := client.ConfigGet()
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve configuration from cilium-agent: %w", err)
	}

	if configResult == nil || configResult.Status == nil {
		return nil, fmt.Errorf("received empty configuration object from cilium-agent")
	}

	return configResult.Status, nil
}
