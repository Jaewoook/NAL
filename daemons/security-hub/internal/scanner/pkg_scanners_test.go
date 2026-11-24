package scanner

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jaewoook/security-hub/internal/models"
)

func TestBrewScanner_OutdatedAndBrokenLinkage(t *testing.T) {
	runner := &fakeRunner{
		handler: func(name string, args ...string) ([]byte, error) {
			cmdLine := name + " " + strings.Join(args, " ")
			switch {
			case strings.Contains(cmdLine, "brew info --json=v2 --installed"):
				return []byte(`{
					"formulae": [
						{"name":"node@22","full_name":"node@22","versions":{"stable":"22.24.0"},"installed":[{"version":"22.23.2_2"}],"deprecated":false},
						{"name":"openssl@3","full_name":"openssl@3","versions":{"stable":"3.4.0"},"installed":[{"version":"3.3.1"}],"deprecated":false}
					],
					"casks": []
				}`), nil
			case strings.Contains(cmdLine, "brew outdated --json=v2"):
				return []byte(`{
					"formulae": [
						{"name":"node@22","installed_versions":["22.23.2_2"],"current_version":"22.24.0"},
						{"name":"openssl@3","installed_versions":["3.3.1"],"current_version":"3.4.0"}
					],
					"casks": []
				}`), nil
			case strings.Contains(cmdLine, "brew linkage --test node@22"):
				return []byte("Missing libraries:\n  /opt/homebrew/opt/simdjson/lib/libsimdjson.33.dylib\n"), errors.New("exit status 1")
			case strings.Contains(cmdLine, "brew linkage --test openssl@3"):
				return []byte(""), nil
			default:
				return nil, nil
			}
		},
	}

	bs := NewBrewScanner(runner)
	items, err := bs.ScanBrew(context.Background())
	if err != nil {
		t.Fatalf("ScanBrew failed: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 brew items, got %d", len(items))
	}
	var nodeItem *struct {
		broken  bool
		details string
	}
	for _, it := range items {
		if it.Name == "node@22" {
			nodeItem = &struct {
				broken  bool
				details string
			}{it.BrokenLinkage, it.LinkageDetails}
		}
	}
	if nodeItem == nil || !nodeItem.broken || !strings.Contains(nodeItem.details, "libsimdjson.33.dylib") {
		t.Fatalf("expected node@22 to be flagged with broken linkage libsimdjson.33.dylib, got %+v", nodeItem)
	}
}

func TestAptScanner_OutdatedManualAndBrokenDependencies(t *testing.T) {
	var sawSudoUpdate bool
	runner := &fakeRunner{
		handler: func(name string, args ...string) ([]byte, error) {
			cmdLine := name + " " + strings.Join(args, " ")
			switch {
			case name == "dpkg-query":
				return []byte(strings.Join([]string{
					"openssl\t3.0.11-1~deb12u2\tinstall\tinstalled",
					"nginx\t1.22.1-9\tinstall\tinstalled",
					"dpkg\t1.21.22\tinstall\tinstalled",
					"linux-image-rpi\t6.6.51\thold\tinstalled",
					"libc6:arm64\t2.36-9+deb12u4\tinstall\tinstalled",
					"libc6:armhf\t2.36-9+deb12u4\tinstall\tinstalled",
					"halfpkg\t\tinstall\thalf-configured",
					"libfoo\t1.0-1\tinstall\tinstalled",
					"nodejs\t18.19.0+dfsg-6\tinstall\tinstalled",
					"removedpkg\t0.1\tdeinstall\tconfig-files",
				}, "\n")), nil
			case cmdLine == "apt-get update -qq":
				return []byte("E: Could not open lock file - open (13: Permission denied)"), errors.New("exit status 100")
			case cmdLine == "sudo -n apt-get update -qq":
				sawSudoUpdate = true
				return []byte(""), nil
			case strings.Contains(cmdLine, "apt list --upgradable"):
				return []byte(strings.Join([]string{
					"Listing...",
					"W: Some warning about /etc/apt/sources.list",
					"openssl/stable-security 3.0.14-1~deb12u1 arm64 [upgradable from: 3.0.11-1~deb12u2]",
					"linux-image-rpi/stable 6.6.62 arm64 [upgradable from: 6.6.51]",
					"libc6/stable 2.36-9+deb12u8 armhf [upgradable from: 2.36-9+deb12u4]",
				}, "\n")), nil
			case strings.Contains(cmdLine, "apt-mark showhold"):
				return []byte("linux-image-rpi\n"), nil
			case strings.Contains(cmdLine, "apt-mark showmanual"):
				return []byte("openssl\nnginx\ndpkg\nlinux-image-rpi\nlibc6:arm64\nlibc6:armhf\nnodejs\n"), nil
			case strings.Contains(cmdLine, "dpkg --audit"):
				return []byte("The following packages are in a mess due to serious problems:\n nginx: broken post-installation script\nThey must be configured using dpkg --configure.\n"), nil
			case strings.Contains(cmdLine, "apt-get -o Debug::NoLocking=true check"):
				return []byte("Reading package lists...\nYou might want to run 'apt --fix-broken install' to correct these.\nThe following packages have unmet dependencies:\n nginx : Pre-Depends: libfoo (>= 2.0) but 1.0-1 is installed\n"), errors.New("exit status 100")
			default:
				return nil, nil
			}
		},
	}

	as := NewAptScanner(runner)
	items, err := as.ScanApt(context.Background())
	if err != nil {
		t.Fatalf("ScanApt failed: %v", err)
	}
	if !sawSudoUpdate {
		t.Fatal("expected apt-get update Permission denied to retry via sudo -n apt-get update -qq")
	}
	if len(items) != 8 {
		t.Fatalf("expected 8 apt items (libfoo/removedpkg excluded), got %d: %+v", len(items), items)
	}

	byName := make(map[string]models.ManagedItem)
	for _, it := range items {
		byName[it.Name] = it
	}

	ossl, ok := byName["openssl"]
	if !ok {
		t.Fatal("expected openssl item")
	}
	if ossl.TargetType != models.TargetApt || !ossl.Outdated || ossl.LatestVersion != "3.0.14-1~deb12u1" {
		t.Fatalf("unexpected openssl item: %+v", ossl)
	}
	if ossl.ReleaseNotesURL != "https://tracker.debian.org/pkg/openssl" {
		t.Fatalf("unexpected ReleaseNotesURL: %q", ossl.ReleaseNotesURL)
	}

	// Held package must not offer an outdated one-click upgrade
	heldPkg, ok := byName["linux-image-rpi"]
	if !ok || heldPkg.Outdated || !strings.Contains(heldPkg.EoL.Message, "Held") {
		t.Fatalf("expected held package linux-image-rpi with Outdated=false and Held EoL message, got %+v", heldPkg)
	}

	// Multiarch: libc6:armhf outdated, libc6:arm64 up-to-date, arch stripped on ReleaseNotesURL
	c6Arm64, ok64 := byName["libc6:arm64"]
	c6Armhf, okhf := byName["libc6:armhf"]
	if !ok64 || !okhf || c6Arm64.Outdated || !c6Armhf.Outdated || c6Armhf.LatestVersion != "2.36-9+deb12u8" {
		t.Fatalf("unexpected multiarch libc6 state: arm64=%+v armhf=%+v", c6Arm64, c6Armhf)
	}
	if c6Armhf.ReleaseNotesURL != "https://tracker.debian.org/pkg/libc6" {
		t.Fatalf("expected stripped arch in ReleaseNotesURL, got %q", c6Armhf.ReleaseNotesURL)
	}

	// Unhealthy dpkg status + Pre-Depends check
	halfPkg, ok := byName["halfpkg"]
	if !ok || !halfPkg.BrokenLinkage || !strings.Contains(halfPkg.LinkageDetails, "half-configured") {
		t.Fatalf("expected halfpkg flagged with dpkg status: half-configured, got %+v", halfPkg)
	}

	ngx, ok := byName["nginx"]
	if !ok || !ngx.BrokenLinkage || !strings.Contains(ngx.LinkageDetails, "Pre-Depends:") {
		t.Fatalf("expected nginx to be flagged with Pre-Depends detail, got %+v", ngx)
	}

	dpkgItem, ok := byName["dpkg"]
	if !ok || dpkgItem.BrokenLinkage {
		t.Fatalf("expected dpkg NOT to be falsely flagged by header prose in dpkg --audit, got %+v", dpkgItem)
	}

	if _, hasLib := byName["libfoo"]; hasLib {
		t.Fatal("expected auto-installed non-upgradable libfoo to be excluded (not falsely matched by Pre-Depends check)")
	}

	// Verify fallback to `apt-get -s -o Debug::NoLocking=true upgrade` when `apt list --upgradable` fails,
	// AND fallback to all packages when `apt-mark showmanual` fails.
	simRunner := &fakeRunner{
		handler: func(name string, args ...string) ([]byte, error) {
			cmdLine := name + " " + strings.Join(args, " ")
			switch {
			case name == "dpkg-query":
				return []byte("openssl\t3.0.11-1~deb12u2\tinstalled\nlibbar\t1.0\tinstalled\n"), nil
			case strings.Contains(cmdLine, "apt list --upgradable"):
				return nil, errors.New("apt wrapper unavailable")
			case strings.Contains(cmdLine, "apt-get -s -o Debug::NoLocking=true upgrade"):
				return []byte("Reading package lists...\nInst openssl [3.0.11-1~deb12u2] (3.0.14-1~deb12u1 Debian-Security:12/bookworm-security [arm64])\n"), nil
			case strings.Contains(cmdLine, "apt-mark showmanual"):
				return nil, errors.New("apt-mark unavailable")
			default:
				return nil, nil
			}
		},
	}
	simItems, err := NewAptScanner(simRunner).ScanApt(context.Background())
	if err != nil || len(simItems) != 2 || !simItems[0].Outdated || simItems[0].LatestVersion != "3.0.14-1~deb12u1" {
		t.Fatalf("expected apt-get -s upgrade & showmanual failure fallback, got err=%v items=%+v", err, simItems)
	}

	// Verify OSV & EoL mapping with Debian epoch + arch suffix
	eco, osvPkg, cleanVer, osvOK := mapItemToOSVPackage(models.ManagedItem{
		TargetType:     models.TargetApt,
		Name:           "matter-hub:armhf",
		CurrentVersion: "1:2.0.57-1~deb12u1",
	})
	if !osvOK || eco != "npm" || osvPkg != "home-assistant-matter-hub" || cleanVer != "2.0.57" {
		t.Fatalf("unexpected OSV mapping for Debian epoch/arch: eco=%q pkg=%q ver=%q ok=%v", eco, osvPkg, cleanVer, osvOK)
	}

	// Verify Debian epoch & suffix stripping in EoL mapping
	prod, cycle := mapItemToEoLProductAndCycle(models.ManagedItem{
		TargetType:     models.TargetApt,
		Name:           "openssl",
		CurrentVersion: "1:3.0.11-1~deb12u2",
	})
	if prod != "openssl" || cycle != "3.0" {
		t.Fatalf("expected openssl cycle 3.0 from Debian epoch version, got (%q, %q)", prod, cycle)
	}
	nProd, nCycle := mapItemToEoLProductAndCycle(models.ManagedItem{
		TargetType:     models.TargetApt,
		Name:           "nodejs",
		CurrentVersion: "18.19.0+dfsg-6",
	})
	if nProd != "nodejs" || nCycle != "18" {
		t.Fatalf("expected nodejs cycle 18, got (%q, %q)", nProd, nCycle)
	}

	// Verify graceful no-op on non-Debian hosts (e.g. macOS without dpkg-query)
	noAptRunner := &fakeRunner{
		handler: func(name string, args ...string) ([]byte, error) {
			if name == "dpkg-query" {
				return nil, errors.New("executable file not found")
			}
			return nil, nil
		},
	}
	noItems, err := NewAptScanner(noAptRunner).ScanApt(context.Background())
	if err != nil || len(noItems) != 0 {
		t.Fatalf("expected nil, nil when dpkg-query is absent, got items=%v err=%v", noItems, err)
	}
}
