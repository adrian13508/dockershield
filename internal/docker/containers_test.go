package docker

import "testing"

func TestIsDockerSocket(t *testing.T) {
	cases := map[string]bool{
		"/var/run/docker.sock":       true,
		"/run/docker.sock":           true,
		"/var/run":                   true, // directory containing the socket
		"/run/":                      true,
		"/":                          true,
		"/run/user/1000/docker.sock": true, // rootless
		"/run/podman/podman.sock":    true,
		"/var/lib/postgresql/data":   false,
		"/var/run/postgresql":        false,
		"/srv/app/docker.sock.bak":   false,
		"":                           false,
	}
	for source, want := range cases {
		if got := isDockerSocket(source); got != want {
			t.Errorf("isDockerSocket(%q) = %v, want %v", source, got, want)
		}
	}
}
