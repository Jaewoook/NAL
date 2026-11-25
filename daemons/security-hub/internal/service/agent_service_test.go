package service_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jaewoook/security-hub/internal/service"
)

func TestAgentService_GenerateLaunchdAndSystemd(t *testing.T) {
	opts := service.AgentServiceOptions{
		BinaryPath:   "/usr/local/bin/security-hub",
		WorkingDir:   "/var/lib/security-hub",
		Name:         "MacStudio-M2",
		Host:         "0.0.0.0",
		Port:         10247,
		Token:        "super-secret-token",
		HubURL:       "http://hub.lan:10311",
		AdvertiseURL: "http://192.168.1.50:10247",
	}

	// 1. Launchd plist verification (token stored in EnvironmentVariables, NEVER in ProgramArguments)
	plist := service.GenerateAgentLaunchdPlist(opts)
	if !strings.Contains(plist, "me.jaewook.nal.security-hub-agent") {
		t.Errorf("expected AgentLaunchdLabel in plist, got: %s", plist)
	}
	if strings.Contains(plist, "<string>-token</string>") {
		t.Fatalf("did not expect -token CLI flag in launchd ProgramArguments:\n%s", plist)
	}
	for _, expected := range []string{
		"<string>agent</string>",
		"<string>run</string>",
		"<string>-host</string>",
		"<string>0.0.0.0</string>",
		"<string>-port</string>",
		"<string>10247</string>",
		"<key>SECURITY_HUB_AGENT_TOKEN</key>",
		"<string>super-secret-token</string>",
		"<string>-hub</string>",
		"<string>http://hub.lan:10311</string>",
		"<string>-name</string>",
		"<string>MacStudio-M2</string>",
		"<string>-advertise-url</string>",
		"<string>http://192.168.1.50:10247</string>",
		"/var/lib/security-hub/security-hub-agent.stdout.log",
		"/var/lib/security-hub/security-hub-agent.stderr.log",
	} {
		if !strings.Contains(plist, expected) {
			t.Errorf("expected plist to contain %q, but it did not:\n%s", expected, plist)
		}
	}

	if service.AgentService.GenerateLaunchdPlist(opts) != plist {
		t.Errorf("AgentService.GenerateLaunchdPlist mismatch")
	}

	// 2. Systemd unit verification (token passed via Environment/EnvironmentFile, NEVER ExecStart -token)
	unit := service.GenerateAgentSystemdUnit(opts)
	if strings.Contains(unit, "ExecStart=/usr/local/bin/security-hub agent run -host 0.0.0.0 -port 10247 -token") {
		t.Fatalf("did not expect -token in ExecStart:\n%s", unit)
	}
	for _, expected := range []string{
		"[Unit]",
		"[Service]",
		"ExecStart=/usr/local/bin/security-hub agent run",
		"-host 0.0.0.0",
		"-port 10247",
		"Environment=SECURITY_HUB_AGENT_TOKEN=super-secret-token",
		"-hub http://hub.lan:10311",
		"-name MacStudio-M2",
		"-advertise-url http://192.168.1.50:10247",
		"Restart=always",
		"[Install]",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(unit, expected) {
			t.Errorf("expected systemd unit to contain %q, but it did not:\n%s", expected, unit)
		}
	}

	if service.GenerateSystemdUnit(opts) != unit {
		t.Errorf("GenerateSystemdUnit alias mismatch")
	}
	if service.AgentService.GenerateSystemdUnit(opts) != unit {
		t.Errorf("AgentService.GenerateSystemdUnit mismatch")
	}
}

func TestAgentService_InstallCustomPathAndRestrictedPermissions(t *testing.T) {
	tmpDir := t.TempDir()
	plistPath := filepath.Join(tmpDir, "custom-agent-service.plist")

	opts := service.AgentServiceOptions{
		BinaryPath: "/usr/local/bin/security-hub",
		WorkingDir: tmpDir,
		Host:       "127.0.0.1",
		Port:       10247,
		Token:      "tok123",
		HubURL:     "http://hub.lan:10311",
		CustomPath: plistPath,
	}

	if err := service.InstallAgent(opts); err != nil {
		t.Fatalf("InstallAgent with .plist CustomPath failed: %v", err)
	}

	st, err := os.Stat(plistPath)
	if err != nil {
		t.Fatalf("failed to stat custom plist service file: %v", err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 permissions on installed plist file, got %o", st.Mode().Perm())
	}

	content, err := os.ReadFile(plistPath)
	if err != nil {
		t.Fatalf("failed to read installed custom plist file: %v", err)
	}
	sContent := string(content)
	if !strings.Contains(sContent, "agent") || !strings.Contains(sContent, "tok123") {
		t.Fatalf("installed plist content missing expected fields: %s", sContent)
	}

	// Custom systemd .service on Linux creates a 0600 EnvironmentFile instead of inlining the secret
	systemdPath := filepath.Join(tmpDir, "security-hub-agent.service")
	optsSystemd := opts
	optsSystemd.CustomPath = systemdPath
	if err := service.InstallAgent(optsSystemd); err != nil {
		t.Fatalf("InstallAgent with .service CustomPath failed: %v", err)
	}
	sysSt, err := os.Stat(systemdPath)
	if err != nil {
		t.Fatalf("failed to stat custom systemd file: %v", err)
	}
	if sysSt.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 permissions on installed service file, got %o", sysSt.Mode().Perm())
	}
	sysContentBytes, err := os.ReadFile(systemdPath)
	if err != nil {
		t.Fatalf("failed to read installed service file: %v", err)
	}
	sysContent := string(sysContentBytes)
	envPath := systemdPath + ".env"
	if !strings.Contains(sysContent, "EnvironmentFile=") || strings.Contains(sysContent, "tok123") {
		t.Fatalf("expected systemd unit to reference EnvironmentFile without inlining secret: %s", sysContent)
	}
	envSt, envErr := os.Stat(envPath)
	if envErr != nil || envSt.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 permissions on env file %s, got err=%v st=%v", envPath, envErr, envSt)
	}
	envBytes, envReadErr := os.ReadFile(envPath)
	if envReadErr != nil || !strings.Contains(string(envBytes), "tok123") {
		t.Fatalf("expected env file to contain token, got err=%v content=%q", envReadErr, string(envBytes))
	}
}

func TestAgentService_SystemdWhitespaceQuoting(t *testing.T) {
	opts := service.AgentServiceOptions{
		BinaryPath: "/opt/My Security Hub/security-hub",
		WorkingDir: "/var/lib/security-hub",
		Name:       "Mac Studio M2",
		Token:      "super secret token",
		HubURL:     "http://hub.lan:10311",
	}

	unit := service.GenerateAgentSystemdUnit(opts)
	for _, expected := range []string{
		`ExecStart="/opt/My Security Hub/security-hub" agent run`,
		`-name "Mac Studio M2"`,
		`Environment="SECURITY_HUB_AGENT_TOKEN=super secret token"`,
		`-hub http://hub.lan:10311`,
	} {
		if !strings.Contains(unit, expected) {
			t.Errorf("expected systemd unit to contain %q, but it did not:\n%s", expected, unit)
		}
	}
}

func TestAgentService_SystemdUserVsSystemTarget(t *testing.T) {
	optsSystem := service.AgentServiceOptions{
		BinaryPath: "/usr/local/bin/security-hub",
		IsUser:     false,
	}
	unitSystem := service.GenerateAgentSystemdUnit(optsSystem)
	if !strings.Contains(unitSystem, "WantedBy=multi-user.target") {
		t.Fatalf("expected system unit to have WantedBy=multi-user.target, got:\n%s", unitSystem)
	}

	optsUser := service.AgentServiceOptions{
		BinaryPath: "/usr/local/bin/security-hub",
		IsUser:     true,
	}
	unitUser := service.GenerateAgentSystemdUnit(optsUser)
	if !strings.Contains(unitUser, "WantedBy=default.target") {
		t.Fatalf("expected user unit to have WantedBy=default.target, got:\n%s", unitUser)
	}
	if strings.Contains(unitUser, "WantedBy=multi-user.target") {
		t.Fatalf("did not expect user unit to have WantedBy=multi-user.target, got:\n%s", unitUser)
	}
}

func TestAgentService_LaunchdPlistXMLEntityEscaping(t *testing.T) {
	opts := service.AgentServiceOptions{
		BinaryPath: "/usr/local/bin/security-hub",
		WorkingDir: "/var/lib/security-hub",
		Name:       "Node & <Test> 'Special'",
		Token:      "tok&<val>\"quote'",
	}

	plist := service.GenerateAgentLaunchdPlist(opts)
	if strings.Contains(plist, "tok&<val>") {
		t.Fatalf("expected unescaped & and < to be absent from plist, got:\n%s", plist)
	}
	if !strings.Contains(plist, "Node &amp; &lt;Test&gt; &#39;Special&#39;") {
		t.Fatalf("expected XML entity escaped node name, got:\n%s", plist)
	}
	if !strings.Contains(plist, "tok&amp;&lt;val&gt;&#34;quote&#39;") {
		t.Fatalf("expected XML entity escaped token, got:\n%s", plist)
	}
}

func TestAgentService_SystemdDollarSignEscaping(t *testing.T) {
	opts := service.AgentServiceOptions{
		BinaryPath: "/usr/local/bin/security-hub",
		Token:      "my$secret$token",
		Name:       "node$1",
	}

	unit := service.GenerateAgentSystemdUnit(opts)
	if !strings.Contains(unit, "Environment=SECURITY_HUB_AGENT_TOKEN=my$$secret$$token") {
		t.Fatalf("expected $ to be escaped as $$ in systemd token env, got:\n%s", unit)
	}
	if !strings.Contains(unit, "-name node$$1") {
		t.Fatalf("expected $ to be escaped as $$ in systemd name, got:\n%s", unit)
	}
}

func TestAgentService_SystemdWorkingDirectoryQuoting(t *testing.T) {
	opts := service.AgentServiceOptions{
		BinaryPath: "/usr/local/bin/security-hub",
		WorkingDir: "/volume1/docker/security hub",
		Name:       "SynologyAgent",
	}

	unit := service.GenerateAgentSystemdUnit(opts)
	if !strings.Contains(unit, `WorkingDirectory="/volume1/docker/security hub"`) {
		t.Fatalf("expected quoted WorkingDirectory for paths with whitespace, got:\n%s", unit)
	}
}

func TestAgentService_SystemdBackslashQuoting(t *testing.T) {
	opts := service.AgentServiceOptions{
		BinaryPath: `C:\Program Files\SecurityHub\security-hub.exe`,
		Token:      `secret\token`,
	}
	unit := service.GenerateAgentSystemdUnit(opts)
	if !strings.Contains(unit, `Environment="SECURITY_HUB_AGENT_TOKEN=secret\\token"`) {
		t.Fatalf("expected backslash to be quoted and escaped in systemd unit env, got:\n%s", unit)
	}
}

func TestAgentService_RejectsDirectiveInjectionAndUnsafeUser(t *testing.T) {
	badOpts := []service.AgentServiceOptions{
		{Name: "node1\nExecStartPre=/bin/evil"},
		{Token: "tok\r\nEnvironment=EVIL=1"},
		{User: "root\nExecStart=/evil"},
		{User: "bad user;id"},
		{WorkingDir: "/tmp/ok\x00dir"},
	}
	for _, o := range badOpts {
		o.CustomPath = filepath.Join(t.TempDir(), "test.plist")
		if err := service.InstallAgent(o); err == nil {
			t.Fatalf("expected InstallAgent to reject injection/invalid user in opts %+v", o)
		}
	}

	// Defense in depth: GenerateAgentSystemdUnit strips newlines and ignores invalid User even when called directly
	unit := service.GenerateAgentSystemdUnit(service.AgentServiceOptions{
		Name: "node\nExecStartPre=/evil",
		User: "bad user",
	})
	if strings.Contains(unit, "\nExecStartPre=") || strings.Contains(unit, "User=bad user") {
		t.Fatalf("expected directive injection and invalid User stripped from rendered systemd unit:\n%s", unit)
	}
}

func TestHubLaunchdPlist_XMLEntityEscaping(t *testing.T) {
	plist := service.GenerateLaunchdPlist("/usr/local/bin/hub & <app>", "/var/lib/hub & dir")
	if strings.Contains(plist, "/usr/local/bin/hub & <app>") {
		t.Fatalf("expected unescaped & and < to be absent from Hub plist, got:\n%s", plist)
	}
	if !strings.Contains(plist, "/usr/local/bin/hub &amp; &lt;app&gt;") {
		t.Fatalf("expected XML entity escaped binary path, got:\n%s", plist)
	}
	if !strings.Contains(plist, "/var/lib/hub &amp; dir") {
		t.Fatalf("expected XML entity escaped working dir, got:\n%s", plist)
	}

	daemonPlist := service.GenerateLaunchdPlistWithUser("/usr/local/bin/security-hub", "/opt/nal/security-hub", "jaewookahn", "/Users/jaewookahn")
	for _, want := range []string{
		"<key>UserName</key>",
		"<string>jaewookahn</string>",
		"<key>HOME</key>",
		"<string>/Users/jaewookahn</string>",
		"<string>hub</string>",
		"<string>run</string>",
	} {
		if !strings.Contains(daemonPlist, want) {
			t.Fatalf("expected LaunchDaemon plist to contain %q, got:\n%s", want, daemonPlist)
		}
	}
}

func TestAgentService_SystemdEnvFileSingleEscaping(t *testing.T) {
	tmpDir := t.TempDir()
	servicePath := filepath.Join(tmpDir, "security-hub-agent.service")
	opts := service.AgentServiceOptions{
		BinaryPath: "/usr/local/bin/security-hub",
		WorkingDir: tmpDir,
		Token:      `sec\ret"val$1`,
		CustomPath: servicePath,
	}
	if err := service.InstallAgent(opts); err != nil {
		t.Fatalf("InstallAgent failed: %v", err)
	}
	envPath := servicePath + ".env"
	st, err := os.Stat(envPath)
	if err != nil {
		t.Fatalf("expected systemd .env file to be created: %v", err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 permissions on .env file, got %o", st.Mode().Perm())
	}
	envBytes, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	expected := "SECURITY_HUB_AGENT_TOKEN=\"sec\\\\ret\\\"val$1\"\n"
	if string(envBytes) != expected {
		t.Fatalf("unexpected .env file content:\ngot:  %q\nwant: %q", string(envBytes), expected)
	}
}

type mockExitCodeErr int

func (e mockExitCodeErr) Error() string { return "exit status" }
func (e mockExitCodeErr) ExitCode() int { return int(e) }

func TestService_LaunchdStopAndRestartHandlesExitStatus3(t *testing.T) {
	restoreSysPlist := service.SetSystemPlistPath(filepath.Join(t.TempDir(), "nonexistent-system.plist"))
	defer restoreSysPlist()

	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	plistPath := service.DefaultPlistPath()
	// Pre-create with overly permissive 0644 to verify InstallPlist atomically resets mode to 0600
	if err := os.MkdirAll(filepath.Dir(plistPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plistPath, []byte("stale"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := service.InstallPlist(plistPath, "/usr/local/bin/security-hub", tmpHome); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(plistPath); err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("expected atomic overwrite of 0644 plist to reset permissions to 0600, got err=%v perm=%v", err, st)
	}
	agentPlistPath := service.DefaultAgentPlistPath()
	if err := os.WriteFile(agentPlistPath, []byte("stale-agent"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := service.InstallAgent(service.AgentServiceOptions{CustomPath: agentPlistPath, Token: "tok"}); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(agentPlistPath); err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("expected atomic overwrite of 0644 agent plist to reset permissions to 0600, got err=%v perm=%v", err, st)
	}

	// 1. Loaded KeepAlive=true job: Restart unloads directly via `launchctl unload -w <plist>`
	// (avoiding `launchctl stop` respawns before unload) and tolerates exit 3 / unload failed: 5 / exit 113.
	var calls []string
	restore := service.SetCmdRunner(func(name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if len(args) >= 1 && args[0] == "unload" {
			return nil, exec.Command("sh", "-c", "exit 3").Run()
		}
		return []byte(""), nil
	})
	defer restore()

	if err := service.Restart(); err != nil {
		t.Fatalf("expected Restart to succeed when unload handles exit status 3, got: %v", err)
	}
	expectedSeq := []string{
		"launchctl list " + service.LaunchdLabel,
		"launchctl unload -w " + plistPath,
		"launchctl list " + service.LaunchdLabel,
		"launchctl unload -w " + plistPath,
		"launchctl load -w " + plistPath,
		"launchctl start " + service.LaunchdLabel,
	}
	if len(calls) != len(expectedSeq) {
		t.Fatalf("unexpected launchctl call sequence (%d calls): %v", len(calls), calls)
	}
	for i, want := range expectedSeq {
		if calls[i] != want {
			t.Fatalf("call[%d] = %q; want %q (full sequence: %v)", i, calls[i], want, calls)
		}
	}

	// 2. Completely unloaded service: `launchctl list <label>` returns exit 113 -> no-ops cleanly
	calls = nil
	restoreNotLoaded := service.SetCmdRunner(func(name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if len(args) >= 1 && args[0] == "list" {
			return []byte("Could not find service"), mockExitCodeErr(113)
		}
		return []byte(""), nil
	})
	defer restoreNotLoaded()

	if err := service.StopLaunchdServiceForTest(plistPath, service.LaunchdLabel); err != nil {
		t.Fatalf("expected StopLaunchdServiceForTest on unloaded service to succeed, got: %v", err)
	}
	if len(calls) != 1 || calls[0] != "launchctl list "+service.LaunchdLabel {
		t.Fatalf("expected only 'launchctl list' when service is unloaded, got: %v", calls)
	}

	// 3. Unexpected launchctl list error (e.g. exit status 1 permission denied) propagates instead of returning nil
	restoreListFail := service.SetCmdRunner(func(name string, args ...string) ([]byte, error) {
		if len(args) >= 1 && args[0] == "list" {
			return []byte("ipc permission denied"), errors.New("exit status 1")
		}
		return []byte(""), nil
	})
	defer restoreListFail()

	if err := service.StopLaunchdServiceForTest(plistPath, service.LaunchdLabel); err == nil || !strings.Contains(err.Error(), "ipc permission denied") {
		t.Fatalf("expected non-not-loaded launchctl list error to propagate, got: %v", err)
	}

	// 4. When plist is missing on disk while job is still loaded in launchd, stopLaunchdService calls `launchctl remove <label>`
	calls = nil
	missingPlist := filepath.Join(tmpHome, "missing.plist")
	restoreMissingPlist := service.SetCmdRunner(func(name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return []byte(""), nil
	})
	defer restoreMissingPlist()

	if err := service.StopLaunchdServiceForTest(missingPlist, service.LaunchdLabel); err != nil {
		t.Fatalf("expected StopLaunchdServiceForTest fallback remove to succeed, got: %v", err)
	}
	if len(calls) != 2 || calls[1] != "launchctl remove "+service.LaunchdLabel {
		t.Fatalf("expected fallback 'launchctl remove' when plist is missing, got: %v", calls)
	}

	// 5. Status() matches exact 3rd-column label and does NOT prefix-match AgentLaunchdLabel
	restoreStatus := service.SetCmdRunner(func(name string, args ...string) ([]byte, error) {
		return []byte("PID\tStatus\tLabel\n4321\t0\t" + service.AgentLaunchdLabel + "\n"), nil
	})
	defer restoreStatus()

	hubStatus, err := service.Status()
	if err != nil {
		t.Fatalf("Status() error: %v", err)
	}
	if hubStatus != "not running / not loaded" {
		t.Fatalf("expected Hub Status() not to prefix-match %q, got %q", service.AgentLaunchdLabel, hubStatus)
	}
	agentStatus, err := service.StatusAgent()
	if err != nil {
		t.Fatalf("StatusAgent() error: %v", err)
	}
	if !strings.Contains(agentStatus, service.AgentLaunchdLabel) {
		t.Fatalf("expected StatusAgent() to match %q, got %q", service.AgentLaunchdLabel, agentStatus)
	}
}
