package docker

import (
	"context"
	"fmt"

	"github.com/docker/docker/client"
)

// Client wraps the Docker API client with our custom methods
type Client struct {
	cli *client.Client
	ctx context.Context
}

// NewClient creates a new Docker client connection
// It connects to the Docker socket (usually /var/run/docker.sock)
func NewClient() (*Client, error) {
	// NewClientWithOpts creates a client from environment variables
	// It will automatically use DOCKER_HOST or default to unix:///var/run/docker.sock
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %w", err)
	}

	// Ping Docker to verify connection
	ctx := context.Background()
	_, err = cli.Ping(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Docker daemon (is Docker running?): %w", err)
	}

	return &Client{
		cli: cli,
		ctx: ctx,
	}, nil
}

// Close closes the Docker client connection
func (c *Client) Close() error {
	if c.cli != nil {
		return c.cli.Close()
	}
	return nil
}

// GetServerVersion returns Docker server version info
func (c *Client) GetServerVersion() (string, error) {
	version, err := c.cli.ServerVersion(c.ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get Docker version: %w", err)
	}
	return version.Version, nil
}
