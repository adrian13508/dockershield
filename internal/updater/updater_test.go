package updater

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const archiveName = "skobel_9.9.9_linux_x86_64.tar.gz"

func makeArchive(t *testing.T, content string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: binaryName, Mode: 0755, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// serve returns a release server for the archive with the given checksums.txt
func serve(t *testing.T, archive []byte, checksums string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch filepath.Base(r.URL.Path) {
		case archiveName:
			_, _ = w.Write(archive)
		case checksumsFile:
			if checksums == "" {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte(checksums))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func installedBinary(t *testing.T) string {
	t.Helper()
	target := filepath.Join(t.TempDir(), binaryName)
	if err := os.WriteFile(target, []byte("old"), 0755); err != nil {
		t.Fatal(err)
	}
	return target
}

func TestInstallVerified(t *testing.T) {
	archive := makeArchive(t, "new binary")
	good := fmt.Sprintf("%x  %s\n", sha256.Sum256(archive), archiveName)

	cases := []struct {
		name      string
		checksums string
		wantErr   string // empty: update must succeed
	}{
		{"matching checksum", good, ""},
		{"wrong checksum", strings.Repeat("0", 64) + "  " + archiveName + "\n", "checksum mismatch"},
		{"archive not listed", strings.Repeat("0", 64) + "  other.tar.gz\n", "not listed"},
		{"no checksums file", "", "404"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := serve(t, archive, c.checksums)
			target := installedBinary(t)

			err := installVerified(srv.Client(), srv.URL+"/download/v9.9.9/"+archiveName, target)

			got, readErr := os.ReadFile(target)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if string(got) != "new binary" {
					t.Errorf("binary = %q, want the new one", got)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("error = %v, want one containing %q", err, c.wantErr)
			}
			if string(got) != "old" {
				t.Errorf("binary was replaced despite failed verification: %q", got)
			}
		})
	}
}

func TestVerifyChecksumBinaryMarker(t *testing.T) {
	data := []byte("x")
	sums := fmt.Sprintf("%X *%s\n", sha256.Sum256(data), "a.tar.gz") // uppercase hex, binary-mode marker
	if err := verifyChecksum([]byte(sums), "a.tar.gz", data); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}
