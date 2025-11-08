package docker

import (
	"fmt"

	"github.com/adrian13508/dockershield/pkg/models"
	"github.com/docker/docker/api/types/network"
)

// ListNetworks returns all Docker networks with their configuration
func (c *Client) ListNetworks() ([]models.NetworkInfo, error) {
	// List all networks
	networks, err := c.cli.NetworkList(c.ctx, network.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list networks: %w", err)
	}

	var result []models.NetworkInfo

	for _, net := range networks {
		// Inspect network for detailed info
		inspect, err := c.cli.NetworkInspect(c.ctx, net.ID, network.InspectOptions{})
		if err != nil {
			fmt.Printf("Warning: failed to inspect network %s: %v\n", net.Name, err)
			continue
		}

		// Extract subnet/gateway from IPAM config
		subnet := ""
		gateway := ""
		if len(inspect.IPAM.Config) > 0 {
			subnet = inspect.IPAM.Config[0].Subnet
			gateway = inspect.IPAM.Config[0].Gateway
		}

		// Get container IDs in this network
		var containerIDs []string
		for containerID := range inspect.Containers {
			containerIDs = append(containerIDs, containerID[:12]) // Short ID
		}

		networkInfo := models.NetworkInfo{
			ID:         net.ID[:12], // Short ID
			Name:       net.Name,
			Driver:     net.Driver,
			Subnet:     subnet,
			Gateway:    gateway,
			Containers: containerIDs,
		}

		result = append(result, networkInfo)
	}

	return result, nil
}
