package portal

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInstaller(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("installer targets Linux and macOS")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash unavailable")
	}
	script, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, os, arch, version, asset, wantError string
		corrupt, noRelease, shasumOnly            bool
	}{
		{name: "linux amd64", os: "Linux", arch: "x86_64", asset: "portal-linux-amd64"},
		{name: "linux arm64", os: "Linux", arch: "aarch64", asset: "portal-linux-arm64"},
		{name: "mac amd64", os: "Darwin", arch: "x86_64", asset: "portal-darwin-amd64"},
		{name: "mac arm64 pinned", os: "Darwin", arch: "arm64", version: "v1.2.3", asset: "portal-darwin-arm64"},
		{name: "shasum fallback", os: "Darwin", arch: "arm64", asset: "portal-darwin-arm64", shasumOnly: true},
		{name: "bad checksum", os: "Linux", arch: "x86_64", asset: "portal-linux-amd64", corrupt: true, wantError: "checksum mismatch"},
		{name: "missing checksum", os: "Linux", arch: "x86_64", asset: "portal-linux-arm64", wantError: "no valid checksum"},
		{name: "no releases", os: "Linux", arch: "x86_64", noRelease: true, wantError: "could not resolve the latest release"},
		{name: "unsupported arch", os: "Linux", arch: "riscv64", wantError: "only amd64 and arm64"},
		{name: "unsupported os", os: "FreeBSD", arch: "amd64", wantError: "only Linux and macOS"},
		{name: "invalid tag", os: "Linux", arch: "x86_64", version: "../bad", wantError: "invalid release tag"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "tools")
			home := filepath.Join(dir, "home with spaces")
			installDir := filepath.Join(home, ".local", "bin")
			overrideDir := ""
			if tc.version == "v1.2.3" {
				overrideDir = filepath.Join(dir, "custom bin")
				installDir = overrideDir
			}
			for _, path := range []string{bin, installDir} {
				if err := os.MkdirAll(path, 0755); err != nil {
					t.Fatal(err)
				}
			}
			write := func(name, data string, mode os.FileMode) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(dir, name), []byte(data), mode); err != nil {
					t.Fatal(err)
				}
			}
			payload := "#!/bin/sh\necho unexpected execution > \"$FIXTURE/ran\"\n"
			write("binary", payload, 0600)
			digest := fmt.Sprintf("%x", sha256.Sum256([]byte(payload)))
			if tc.corrupt {
				digest = strings.Repeat("0", 64)
			}
			write("SHA256SUMS", digest+"  "+tc.asset+"\n", 0600)
			write("tools/uname", "#!/bin/sh\ncase \"$1\" in -s) echo \"$TEST_OS\";; -m) echo \"$TEST_ARCH\";; *) exit 1;; esac\n", 0755)
			write("tools/curl", `#!/bin/sh
set -eu
output=
url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) output="$2"; shift 2 ;;
    --write-out|--proto|--proto-redir) shift 2 ;;
    --*) shift ;;
    *) url="$1"; shift ;;
  esac
done
printf '%s\n' "$url" >> "$FIXTURE/requests"
case "$url" in
  https://github.com/lab47/portal/releases/latest)
    [ "$NO_RELEASE" != true ] || exit 22
    printf 'https://github.com/lab47/portal/releases/tag/build-42-1' ;;
  https://github.com/lab47/portal/releases/download/*/SHA256SUMS) cp "$FIXTURE/SHA256SUMS" "$output" ;;
  https://github.com/lab47/portal/releases/download/*/portal-*) cp "$FIXTURE/binary" "$output" ;;
  *) exit 22 ;;
esac
`, 0755)
			installed := filepath.Join(installDir, "portal")
			if err := os.WriteFile(installed, []byte("previous installation"), 0755); err != nil {
				t.Fatal(err)
			}
			// Feed stdin as curl | bash would. All network calls are intercepted;
			// checksum verification uses the real system SHA-256 utility.
			path := bin + string(os.PathListSeparator) + os.Getenv("PATH")
			if tc.shasumOnly {
				for _, tool := range []string{"mkdir", "mktemp", "rm", "cp", "chmod", "mv", "shasum"} {
					realTool, err := exec.LookPath(tool)
					if err != nil {
						t.Skipf("%s unavailable for fallback test", tool)
					}
					if err := os.Symlink(realTool, filepath.Join(bin, tool)); err != nil {
						t.Fatal(err)
					}
				}
				path = bin // Deliberately exclude sha256sum.
			}
			cmd := exec.Command(bash)
			cmd.Stdin = strings.NewReader(string(script))
			cmd.Env = append(os.Environ(), "PATH="+path, "HOME="+home, "TMPDIR="+dir,
				"FIXTURE="+dir, "TEST_OS="+tc.os, "TEST_ARCH="+tc.arch, "NO_RELEASE="+fmt.Sprint(tc.noRelease),
				"PORTAL_VERSION="+tc.version, "PORTAL_INSTALL_DIR="+overrideDir)
			out, err := cmd.CombinedOutput()
			data, readErr := os.ReadFile(installed)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if tc.wantError != "" {
				if err == nil || !strings.Contains(string(out), tc.wantError) || string(data) != "previous installation" {
					t.Fatalf("failed install changed binary or wrong error: %s, %v, %s", out, err, data)
				}
			} else {
				if err != nil || string(data) != payload || !strings.Contains(string(out), "Installed "+installDir+"/portal") {
					t.Fatalf("install: %s, %v, %s", out, err, data)
				}
				info, err := os.Stat(installed)
				if err != nil || info.Mode().Perm() != 0755 {
					t.Fatalf("installed permissions: %v, %v", info, err)
				}
				requests, err := os.ReadFile(filepath.Join(dir, "requests"))
				version := tc.version
				if version == "" {
					version = "build-42-1"
				}
				if err != nil || !strings.Contains(string(requests), "/download/"+version+"/"+tc.asset) || (tc.version != "" && strings.Contains(string(requests), "/releases/latest")) {
					t.Fatalf("wrong release/platform requested: %s, %v", requests, err)
				}
			}
			if _, err := os.Stat(filepath.Join(dir, "ran")); !os.IsNotExist(err) {
				t.Fatal("installer executed the downloaded binary")
			}
			for _, pattern := range []string{filepath.Join(dir, "portal-install.*"), filepath.Join(installDir, ".portal.*")} {
				leftovers, err := filepath.Glob(pattern)
				if err != nil || len(leftovers) != 0 {
					t.Fatalf("temporary files leaked: %v, %v", leftovers, err)
				}
			}
		})
	}
}
