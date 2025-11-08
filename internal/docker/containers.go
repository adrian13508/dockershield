package docker

import (
	"fmt"
	"strings"

	"github.com/adrian13508/dockershield/pkg/models"
	"github.com/docker/docker/api/types/container"
)

// ListContainers returns all running containers with their security info
func (c *Client) ListContainers() ([]models.Container, error) {
	// List all containers (running and stopped)
	containers, err := c.cli.ContainerList(c.ctx, container.ListOptions{
		All: true, // Include stopped containers
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	var result []models.Container

	// Inspect each container to get detailed information
	for _, ctr := range containers {
		// Get full container details
		inspect, err := c.cli.ContainerInspect(c.ctx, ctr.ID)
		if err != nil {
			// Log but don't fail - continue with other containers
			fmt.Printf("Warning: failed to inspect container %s: %v\n", ctr.ID, err)
			continue
		}

		// Extract port bindings
		ports := extractPortBindings(inspect)

		// Build our container model
		containerInfo := models.Container{
			ID:          ctr.ID[:12],                           // Short ID (first 12 chars)
			Name:        strings.TrimPrefix(ctr.Names[0], "/"), // Remove leading slash
			Image:       ctr.Image,
			State:       ctr.State,
			NetworkMode: string(inspect.HostConfig.NetworkMode),
			Ports:       ports,
			Networks:    getContainerNetworks(inspect),
			// CreatedAt is parsed from string in Docker API
			// For now, we'll use current time as placeholder
			// TODO: Parse inspect.Created string properly
		}

		result = append(result, containerInfo)
	}

	return result, nil
}

// extractPortBindings converts Docker port bindings to our model
func extractPortBindings(inspect container.InspectResponse) []models.PortBinding {
	var bindings []models.PortBinding

	// Docker stores ports in NetworkSettings.Ports
	// Format: "80/tcp" -> [{"HostIp": "0.0.0.0", "HostPort": "8080"}]
	for port, bindingList := range inspect.NetworkSettings.Ports {
		if len(bindingList) == 0 {
			// Port exposed but not bound to host
			continue
		}

		for _, binding := range bindingList {
			// Split port string "80/tcp" -> "80" and "tcp"
			portParts := strings.Split(string(port), "/")
			containerPort := portParts[0]
			protocol := portParts[1]

			pb := models.PortBinding{
				HostIP:        binding.HostIP,
				HostPort:      binding.HostPort,
				ContainerPort: containerPort,
				Protocol:      protocol,
				ExposureType:  classifyExposure(binding.HostIP),
				RiskLevel:     models.RiskInfo, // Will be calculated later
				RiskReason:    "",
			}

			bindings = append(bindings, pb)
		}
	}

	return bindings
}

// classifyExposure determines how a port is exposed based on IP
func classifyExposure(hostIP string) models.ExposureType {
	switch hostIP {
	case "0.0.0.0", "::":
		return models.ExposurePublic
	case "127.0.0.1", "::1":
		return models.ExposureLocalhost
	default:
		return models.ExposureSpecificIP
	}
}

// getContainerNetworks extracts network names from container
func getContainerNetworks(inspect container.InspectResponse) []string {
	var networks []string
	for networkName := range inspect.NetworkSettings.Networks {
		networks = append(networks, networkName)
	}
	return networks
}
