package system

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// DaemonTCP holds the TCP listeners configured for dockerd
type DaemonTCP struct {
	Hosts     []string
	TLSVerify bool
}

// DockerDaemonTCP looks for tcp:// listeners in /etc/docker/daemon.json and
// on the command line of a running dockerd. Unreadable sources are skipped.
func DockerDaemonTCP() DaemonTCP {
	var result DaemonTCP

	if data, err := os.ReadFile("/etc/docker/daemon.json"); err == nil {
		hosts, tls := parseDaemonJSON(data)
		result.Hosts = append(result.Hosts, hosts...)
		result.TLSVerify = result.TLSVerify || tls
	}

	cmdlines, _ := filepath.Glob("/proc/[0-9]*/cmdline")
	for _, path := range cmdlines {
		data, err := os.ReadFile(path)
		if err != nil || len(data) == 0 {
			continue
		}
		args := strings.Split(string(bytes.TrimRight(data, "\x00")), "\x00")
		if filepath.Base(args[0]) != "dockerd" {
			continue
		}
		hosts, tls := parseDockerdArgs(args[1:])
		result.Hosts = append(result.Hosts, hosts...)
		result.TLSVerify = result.TLSVerify || tls
	}

	return result
}

// parseDaemonJSON extracts tcp:// hosts and tlsverify from daemon.json
func parseDaemonJSON(data []byte) (hosts []string, tlsVerify bool) {
	var cfg struct {
		Hosts     []string `json:"hosts"`
		TLSVerify bool     `json:"tlsverify"`
	}
	if json.Unmarshal(data, &cfg) != nil {
		return nil, false
	}
	for _, h := range cfg.Hosts {
		if strings.HasPrefix(h, "tcp://") {
			hosts = append(hosts, h)
		}
	}
	return hosts, cfg.TLSVerify
}

// parseDockerdArgs extracts tcp:// hosts and --tlsverify from dockerd arguments
func parseDockerdArgs(args []string) (hosts []string, tlsVerify bool) {
	for _, arg := range args {
		if arg == "--tlsverify" || arg == "--tlsverify=true" {
			tlsVerify = true
			continue
		}
		// Covers "-H tcp://...", "-H=tcp://..." and "--host=tcp://..."
		arg = strings.TrimPrefix(strings.TrimPrefix(arg, "--host="), "-H=")
		if strings.HasPrefix(arg, "tcp://") {
			hosts = append(hosts, arg)
		}
	}
	return hosts, tlsVerify
}
