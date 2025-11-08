package diagnostics

import (
	"context"
	"fmt"
	"os"

	"github.com/adrian13508/dockershield/internal/docker"
)

// CheckDocker performs Docker-related diagnostic checks
func CheckDocker() *DockerInfo {
	info := &DockerInfo{}

	// Try to create Docker client
	client, err := docker.NewClient()
	if err != nil {
		// Docker not accessible
		info.Installed = CheckResult{
			Status:  StatusFail,
			Value:   "no",
			Message: "Docker is not accessible",
			Fix:     "Install Docker: https://docs.docker.com/engine/install/",
		}
		info.DaemonRunning = CheckResult{
			Status:  StatusFail,
			Value:   "no",
			Message: "Docker daemon is not running",
		}
		info.SocketAccessible = checkDockerSocket()
		info.APIVersion = CheckResult{Status: StatusSkipped, Value: "N/A"}
		info.CanListContainers = CheckResult{Status: StatusSkipped, Value: "N/A"}
		info.CanListNetworks = CheckResult{Status: StatusSkipped, Value: "N/A"}
		return info
	}
	defer client.Close()

	// Docker is accessible
	info.Installed = CheckResult{
		Status:  StatusPass,
		Value:   "yes",
		Message: "Docker is installed and accessible",
	}

	// Check if daemon is running (if we got here, it is)
	info.DaemonRunning = CheckResult{
		Status:  StatusPass,
		Value:   "yes",
		Message: "Docker daemon is running",
	}

	// Check socket accessibility
	info.SocketAccessible = checkDockerSocket()

	// Get API version
	version, err := client.GetServerVersion()
	if err != nil {
		info.APIVersion = CheckResult{
			Status:  StatusWarning,
			Value:   "unknown",
			Message: "Could not determine Docker API version",
		}
	} else {
		info.APIVersion = CheckResult{
			Status:  StatusPass,
			Value:   version,
			Message: fmt.Sprintf("Docker Engine: %s", version),
		}
	}

	// Test listing containers
	containers, err := client.ListContainers()
	if err != nil {
		info.CanListContainers = CheckResult{
			Status:  StatusFail,
			Value:   "no",
			Message: "Cannot list containers",
			Fix:     "Check Docker permissions",
		}
	} else {
		info.CanListContainers = CheckResult{
			Status:  StatusPass,
			Value:   "yes",
			Message: fmt.Sprintf("Can list containers (%d running)", len(containers)),
		}
	}

	// Test listing networks
	networks, err := client.ListNetworks()
	if err != nil {
		info.CanListNetworks = CheckResult{
			Status:  StatusWarning,
			Value:   "no",
			Message: "Cannot list networks",
		}
	} else {
		info.CanListNetworks = CheckResult{
			Status:  StatusPass,
			Value:   "yes",
			Message: fmt.Sprintf("Can list networks (%d networks)", len(networks)),
		}
	}

	return info
}

// checkDockerSocket checks if Docker socket is accessible
func checkDockerSocket() CheckResult {
	socketPath := "/var/run/docker.sock"

	// Check if socket exists
	info, err := os.Stat(socketPath)
	if err != nil {
		if os.IsNotExist(err) {
			return CheckResult{
				Status:  StatusFail,
				Value:   "no",
				Message: "Docker socket not found",
				Fix:     "Ensure Docker is installed and running",
			}
		}
		return CheckResult{
			Status:  StatusWarning,
			Value:   "unknown",
			Message: "Cannot stat Docker socket",
		}
	}

	// Check if it's a socket
	if info.Mode()&os.ModeSocket == 0 {
		return CheckResult{
			Status:  StatusFail,
			Value:   "no",
			Message: fmt.Sprintf("%s exists but is not a socket", socketPath),
		}
	}

	// Try to access it
	_, err = os.OpenFile(socketPath, os.O_RDWR, 0)
	if err != nil {
		return CheckResult{
			Status:  StatusWarning,
			Value:   "limited",
			Message: "Docker socket exists but may have permission issues",
			Fix:     "Add user to docker group: sudo usermod -aG docker $USER",
		}
	}

	return CheckResult{
		Status:  StatusPass,
		Value:   socketPath,
		Message: fmt.Sprintf("Docker socket accessible: %s", socketPath),
	}
}

// GetDockerClient is a helper that returns a Docker client if available
func GetDockerClient() (*docker.Client, error) {
	return docker.NewClient()
}

// PingDocker checks if Docker daemon is responsive
func PingDocker(ctx context.Context, client *docker.Client) error {
	// Try to get version as a ping
	_, err := client.GetServerVersion()
	return err
}
