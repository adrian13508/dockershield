package docker

import (
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/adrian13508/skobel/internal/analyzer"
	"github.com/adrian13508/skobel/pkg/models"
	"github.com/docker/docker/api/types/container"
)

// ListContainers returns all containers, running or not, with their security info
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
		inspect, err := c.cli.ContainerInspect(c.ctx, ctr.ID)
		if err != nil {
			// Report on stderr so JSON/Prometheus output on stdout stays valid
			fmt.Fprintf(os.Stderr, "Warning: failed to inspect container %s: %v\n", ctr.ID, err)
			continue
		}

		name := ctr.ID
		if len(ctr.Names) > 0 {
			name = strings.TrimPrefix(ctr.Names[0], "/")
		}
		id := ctr.ID
		if len(id) > 12 {
			id = id[:12]
		}
		created, _ := time.Parse(time.RFC3339Nano, inspect.Created)

		containerInfo := models.Container{
			ID:                  id,
			Name:                name,
			Image:               ctr.Image,
			State:               ctr.State,
			Ports:               extractPortBindings(inspect),
			Networks:            getContainerNetworks(inspect),
			CreatedAt:           created,
			DockerSocketMounted: mountsDockerSocket(inspect),
		}
		if inspect.HostConfig != nil {
			containerInfo.NetworkMode = string(inspect.HostConfig.NetworkMode)
		}

		result = append(result, containerInfo)
	}

	return result, nil
}

// extractPortBindings converts Docker port bindings to our model
func extractPortBindings(inspect container.InspectResponse) []models.PortBinding {
	var bindings []models.PortBinding
	if inspect.NetworkSettings == nil {
		return bindings
	}

	// Format: "80/tcp" -> [{"HostIp": "0.0.0.0", "HostPort": "8080"}]
	// A port that is exposed but not published has an empty list.
	for port, bindingList := range inspect.NetworkSettings.Ports {
		for _, binding := range bindingList {
			exposure, scope := analyzer.ClassifyHostIP(binding.HostIP)
			bindings = append(bindings, models.PortBinding{
				HostIP:        binding.HostIP,
				HostPort:      binding.HostPort,
				ContainerPort: port.Port(),
				Protocol:      port.Proto(),
				ExposureType:  exposure,
				AddressScope:  scope,
				RiskLevel:     models.RiskInfo, // set by the analyzer
			})
		}
	}

	// Map iteration order is random; keep output stable
	sort.Slice(bindings, func(i, j int) bool {
		a, b := bindings[i], bindings[j]
		if a.HostPort != b.HostPort {
			return a.HostPort < b.HostPort
		}
		return a.HostIP < b.HostIP
	})
	return bindings
}

// mountsDockerSocket reports whether the Docker socket is mounted into the container
func mountsDockerSocket(inspect container.InspectResponse) bool {
	for _, m := range inspect.Mounts {
		if isDockerSocket(m.Source) {
			return true
		}
	}
	return false
}

// isDockerSocket reports whether mounting source gives access to the Docker
// (or Podman) socket: the socket itself, or one of /, /var, /var/run and
// /run, which contain the default socket.
// Compares paths as written; a socket reached through a symlink
// or a non-default path is missed. Resolve against the daemon's unix://
// host if that turns out to matter.
func isDockerSocket(source string) bool {
	source = path.Clean(source)
	switch source {
	case "/", "/var", "/var/run", "/run":
		return true
	}
	base := path.Base(source)
	return base == "docker.sock" || base == "podman.sock"
}

// getContainerNetworks extracts network names from container
func getContainerNetworks(inspect container.InspectResponse) []string {
	var networks []string
	if inspect.NetworkSettings == nil {
		return networks
	}
	for networkName := range inspect.NetworkSettings.Networks {
		networks = append(networks, networkName)
	}
	sort.Strings(networks)
	return networks
}
