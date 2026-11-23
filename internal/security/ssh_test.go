package security

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestSSHConfigIncludeAndFirstValueWins(t *testing.T) {
	dir := t.TempDir()
	dropIn := filepath.Join(dir, "conf.d")
	if err := os.Mkdir(dropIn, 0700); err != nil {
		t.Fatal(err)
	}
	// cloud-init style drop-in, included before the main settings
	writeFile(t, filepath.Join(dropIn, "50-cloud-init.conf"), "PasswordAuthentication yes\n")
	writeFile(t, filepath.Join(dropIn, "60-other.conf"), "PasswordAuthentication no\nPort=2222\n")
	main := filepath.Join(dir, "sshd_config")
	writeFile(t, main, "# comment\n"+
		"Include "+dropIn+"/*.conf\n"+
		"PasswordAuthentication no\n"+
		"PermitRootLogin prohibit-password\n"+
		"KbdInteractiveAuthentication no\n"+
		"Match User deploy\n"+
		"    PermitRootLogin yes\n"+
		"PermitEmptyPasswords yes\n")

	cfg := &SSHConfig{ConfigFile: main, Port: 22, PasswordAuth: "unknown", PermitRootLogin: "unknown",
		PermitEmptyPassword: "unknown", ChallengeResponse: "unknown"}
	if err := cfg.parseConfig(); err != nil {
		t.Fatal(err)
	}

	if cfg.PasswordAuth != "yes" {
		t.Errorf("PasswordAuth = %q, want yes (first value, from the include, wins)", cfg.PasswordAuth)
	}
	if cfg.Port != 2222 {
		t.Errorf("Port = %d, want 2222 (Keyword=value form in an include)", cfg.Port)
	}
	if cfg.PermitRootLogin != "prohibit-password" {
		t.Errorf("PermitRootLogin = %q, want prohibit-password (Match block must be ignored)", cfg.PermitRootLogin)
	}
	if cfg.PermitEmptyPassword != "unknown" {
		t.Errorf("PermitEmptyPassword = %q, want unknown (after Match)", cfg.PermitEmptyPassword)
	}
	if cfg.ChallengeResponse != "no" {
		t.Errorf("ChallengeResponse = %q, want no (KbdInteractiveAuthentication alias)", cfg.ChallengeResponse)
	}
}

func TestSSHConfigMissingFile(t *testing.T) {
	cfg := &SSHConfig{ConfigFile: filepath.Join(t.TempDir(), "nope")}
	if err := cfg.parseConfig(); err == nil {
		t.Error("expected an error for a missing config file")
	}
}

func TestKbdInteractiveKeepsPasswordLoginsPossible(t *testing.T) {
	has := func(c *SSHConfig) bool {
		for _, issue := range c.Issues {
			if strings.Contains(issue.Issue, "Keyboard-interactive") {
				return true
			}
		}
		return false
	}
	on := &SSHConfig{PasswordAuth: "no", ChallengeResponse: "yes", SecurityScore: 100}
	on.analyzeSecurityPosture()
	if !has(on) {
		t.Error("PasswordAuthentication no with KbdInteractiveAuthentication yes must raise an issue")
	}
	off := &SSHConfig{PasswordAuth: "no", ChallengeResponse: "no", SecurityScore: 100}
	off.analyzeSecurityPosture()
	if has(off) {
		t.Error("no issue expected when keyboard-interactive is off")
	}
}
