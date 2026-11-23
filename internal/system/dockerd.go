package system

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// TCPListener is one TCP address a Docker daemon listens on
type TCPListener struct {
	Host      string // always with the tcp:// prefix
	TLSVerify bool
}

// DockerDaemonTCP looks for TCP listeners in /etc/docker/daemon.json and on
// the command line of every running dockerd. Unreadable sources are skipped.
func DockerDaemonTCP() []TCPListener {
	var jsonHosts []string
	jsonTLS := false
	if data, err := os.ReadFile("/etc/docker/daemon.json"); err == nil {
		jsonHosts, jsonTLS = parseDaemonJSON(data)
	}

	var procs []daemonArgs
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
		procs = append(procs, daemonArgs{hosts, tls})
	}
	return mergeListeners(jsonHosts, jsonTLS, procs)
}

type daemonArgs struct {
	hosts []string
	tls   bool
}

// mergeListeners pairs listeners with TLS verification. One daemon reads its
// settings from both daemon.json and its command line, so tlsverify in either
// place covers hosts given in the other.
// Daemon.json is applied to every dockerd found. A second daemon
// with its own --config-file would inherit tlsverify from /etc/docker; read
// --config-file per process if that setup needs to be told apart.
func mergeListeners(jsonHosts []string, jsonTLS bool, procs []daemonArgs) []TCPListener {
	var result []TCPListener
	anyProcTLS := false
	for _, p := range procs {
		anyProcTLS = anyProcTLS || p.tls
		for _, h := range p.hosts {
			result = append(result, TCPListener{Host: h, TLSVerify: p.tls || jsonTLS})
		}
	}
	for _, h := range jsonHosts {
		result = append(result, TCPListener{Host: h, TLSVerify: jsonTLS || anyProcTLS})
	}
	return result
}

// tcpHost returns the host with a tcp:// prefix if dockerd would listen on
// TCP for it. Like dockerd, it treats a value without a scheme as TCP.
func tcpHost(h string) (string, bool) {
	switch {
	case strings.HasPrefix(h, "tcp://"):
		return h, true
	case h == "" || strings.Contains(h, "://"):
		return "", false
	}
	return "tcp://" + h, true
}

// parseDaemonJSON extracts TCP hosts and tlsverify from daemon.json
func parseDaemonJSON(data []byte) (hosts []string, tlsVerify bool) {
	var cfg struct {
		Hosts     []string `json:"hosts"`
		TLSVerify bool     `json:"tlsverify"`
	}
	if json.Unmarshal(data, &cfg) != nil {
		return nil, false
	}
	for _, h := range cfg.Hosts {
		if h, ok := tcpHost(h); ok {
			hosts = append(hosts, h)
		}
	}
	return hosts, cfg.TLSVerify
}

// parseDockerdArgs extracts TCP hosts and --tlsverify from dockerd arguments.
// Covers "-H value", "--host value", "-H=value" and "--host=value".
func parseDockerdArgs(args []string) (hosts []string, tlsVerify bool) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		var value string
		switch {
		case arg == "--tlsverify" || arg == "--tlsverify=true":
			tlsVerify = true
			continue
		case arg == "-H" || arg == "--host":
			if i+1 == len(args) {
				continue
			}
			i++
			value = args[i]
		case strings.HasPrefix(arg, "--host="):
			value = strings.TrimPrefix(arg, "--host=")
		case strings.HasPrefix(arg, "-H="):
			value = strings.TrimPrefix(arg, "-H=")
		default:
			continue
		}
		if h, ok := tcpHost(value); ok {
			hosts = append(hosts, h)
		}
	}
	return hosts, tlsVerify
}
