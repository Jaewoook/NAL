package notifier

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/smtp"
	"strings"
	"testing"
	"time"

	"github.com/jaewoook/security-hub/internal/config"
	"github.com/jaewoook/security-hub/internal/db"
	"github.com/jaewoook/security-hub/internal/models"
)

func TestAlerter_NotifyScanFindingsDeduplicationAndRollback(t *testing.T) {
	ctx := context.Background()
	store, err := db.NewSpoolStore(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}

	var sentMessages []string
	alerter := NewAlerter(config.EmailConfig{
		Enabled:   true,
		SMTPHost:  "smtp.example.com",
		SMTPPort:  587,
		Username:  "nal@example.com",
		Password:  "secret",
		FromEmail: "nal@example.com",
		ToEmail:   "admin@jaewook.dev",
	}, store)

	alerter.sendMailFunc = func(ctx context.Context, cfg config.EmailConfig, addr string, a smtp.Auth, from string, to []string, msg []byte) error {
		sentMessages = append(sentMessages, string(msg))
		return nil
	}

	scan := &models.ScanResult{
		Items: []models.ManagedItem{
			{
				TargetType:     models.TargetDocker,
				Name:           "cloudflare-tunnel",
				CurrentVersion: "2026.8.0",
				LatestVersion:  "2026.10.2",
				CritCount:      1,
				Vulnerabilities: []models.Vulnerability{
					{ID: "GHSA-cf-1234", Severity: models.SeverityCritical, Summary: "Tunnel compromise", FixedVersion: "2026.10.2"},
				},
			},
			{
				TargetType:     models.TargetDocker,
				Name:           "auth",
				CurrentVersion: "2026.5.3",
				EoL: models.EoLInfo{
					Product:       "authentik",
					Cycle:         "2026.5",
					Status:        models.EoLExpiringSoon,
					EoLDate:       "2026-11-18",
					DaysRemaining: 19,
				},
			},
			{
				TargetType:     models.TargetBrew,
				Name:           "node@22",
				CurrentVersion: "22.23.2_2",
				BrokenLinkage:  true,
				LinkageDetails: "Missing libsimdjson.33.dylib",
			},
		},
	}

	count, err := alerter.NotifyScanFindings(ctx, scan)
	if err != nil {
		t.Fatalf("NotifyScanFindings failed: %v", err)
	}
	if count != 3 || len(sentMessages) != 1 {
		t.Fatalf("expected 3 findings in 1 email, got count=%d emails=%d", count, len(sentMessages))
	}
	if !strings.Contains(sentMessages[0], "GHSA-cf-1234") || !strings.Contains(sentMessages[0], "authentik") || !strings.Contains(sentMessages[0], "node@22") {
		t.Fatalf("email body missing expected findings: %s", sentMessages[0])
	}

	// Second call with identical scan findings should send 0 emails (deduplicated)
	count2, err := alerter.NotifyScanFindings(ctx, scan)
	if err != nil {
		t.Fatalf("second NotifyScanFindings failed: %v", err)
	}
	if count2 != 0 || len(sentMessages) != 1 {
		t.Fatalf("expected 0 new findings and no extra email on duplicate scan, got count=%d emails=%d", count2, len(sentMessages))
	}

	// Node-scoped findings on distinct Raspberry Pi nodes should NOT deduplicate against each other
	piScan := &models.ScanResult{
		Items: []models.ManagedItem{
			{Node: "RPi-01", TargetType: models.TargetApt, Name: "nginx", CurrentVersion: "1.22.1-9", BrokenLinkage: true, LinkageDetails: "unmet dependency"},
			{Node: "RPi-02", TargetType: models.TargetApt, Name: "nginx", CurrentVersion: "1.22.1-9", BrokenLinkage: true, LinkageDetails: "unmet dependency"},
		},
	}
	piCount, err := alerter.NotifyScanFindings(ctx, piScan)
	if err != nil || piCount != 2 || len(sentMessages) != 2 {
		t.Fatalf("expected 2 node-scoped APT findings across RPi-01 and RPi-02, got count=%d err=%v emails=%d", piCount, err, len(sentMessages))
	}
	if !strings.Contains(sentMessages[1], "[RPi-01] nginx") || !strings.Contains(sentMessages[1], "[RPi-02] nginx") || !strings.Contains(sentMessages[1], "APT BROKEN DEPENDENCY") {
		t.Fatalf("expected node labels and APT BROKEN DEPENDENCY in email body:\n%s", sentMessages[1])
	}

	// Rollback alert
	if err := alerter.NotifyDeadManRollback(ctx, "cloudflare-tunnel", "2026.8.0", "2026.10.2", "external probe failed"); err != nil {
		t.Fatalf("NotifyDeadManRollback failed: %v", err)
	}
	if len(sentMessages) != 3 || !strings.Contains(sentMessages[2], "ROLLBACK") {
		t.Fatalf("expected rollback email to be sent, got %d messages", len(sentMessages))
	}
}

func testCert(t *testing.T) tls.Certificate {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "127.0.0.1",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
}

func readRawLine(conn net.Conn) (string, error) {
	var buf []byte
	b := make([]byte, 1)
	for {
		n, err := conn.Read(b)
		if err != nil {
			return string(buf), err
		}
		if n > 0 {
			buf = append(buf, b[0])
			if b[0] == '\n' {
				return string(buf), nil
			}
		}
	}
}

func handleMockSMTPSession(conn net.Conn, sendGreeting bool) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	writeLine := func(s string) {
		_, _ = writer.WriteString(s + "\r\n")
		_ = writer.Flush()
	}

	if sendGreeting {
		writeLine("220 127.0.0.1 ESMTP MockServer")
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.TrimSpace(line)
		upper := strings.ToUpper(cmd)
		switch {
		case strings.HasPrefix(upper, "EHLO") || strings.HasPrefix(upper, "HELO"):
			writeLine("250-127.0.0.1 Hello\r\n250-AUTH PLAIN LOGIN\r\n250 HELP")
		case strings.HasPrefix(upper, "AUTH PLAIN"):
			writeLine("235 2.7.0 Authentication successful")
		case strings.HasPrefix(upper, "MAIL FROM:"):
			writeLine("250 2.1.0 Ok")
		case strings.HasPrefix(upper, "RCPT TO:"):
			writeLine("250 2.1.5 Ok")
		case upper == "DATA":
			writeLine("354 End data with <CR><LF>.<CR><LF>")
			for {
				dataLine, dErr := reader.ReadString('\n')
				if dErr != nil || strings.TrimSpace(dataLine) == "." {
					break
				}
			}
			writeLine("250 2.0.0 Ok: queued")
		case upper == "QUIT":
			writeLine("221 2.0.0 Bye")
			return
		default:
			writeLine("502 5.5.1 Command not implemented")
		}
	}
}

func TestAlerter_DefaultSendMail_SMTPS_Port465(t *testing.T) {
	cert := testCert(t)
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	cfg := config.EmailConfig{
		Enabled:   true,
		SMTPHost:  "127.0.0.1",
		SMTPPort:  465,
		UseTLS:    true,
		Username:  "resend",
		Password:  "api-key",
		FromEmail: "sender@example.com",
		ToEmail:   "dest@example.com",
	}

	alerter := NewAlerter(cfg, nil)
	alerter.dialer = func(ctx context.Context, addr string, isImplicit bool, clientTLS *tls.Config) (net.Conn, error) {
		clientPipe, serverPipe := net.Pipe()
		serverTLS := tls.Server(serverPipe, tlsConf)
		go handleMockSMTPSession(serverTLS, true)
		clientConn := tls.Client(clientPipe, clientTLS)
		return clientConn, nil
	}

	err := alerter.SendTestEmail(context.Background())
	if err != nil {
		t.Fatalf("SendTestEmail over implicit TLS failed: %v", err)
	}
}

func TestAlerter_DefaultSendMail_STARTTLS_Port587(t *testing.T) {
	cert := testCert(t)

	cfg := config.EmailConfig{
		Enabled:   true,
		SMTPHost:  "127.0.0.1",
		SMTPPort:  587,
		UseTLS:    true,
		Username:  "user",
		Password:  "pass",
		FromEmail: "sender@example.com",
		ToEmail:   "dest@example.com",
	}

	alerter := NewAlerter(cfg, nil)
	alerter.dialer = func(ctx context.Context, addr string, isImplicit bool, clientTLS *tls.Config) (net.Conn, error) {
		clientPipe, serverPipe := net.Pipe()
		go func() {
			defer serverPipe.Close()
			_, _ = serverPipe.Write([]byte("220 127.0.0.1 ESMTP MockServer\r\n"))
			line, _ := readRawLine(serverPipe)
			if strings.HasPrefix(strings.ToUpper(line), "EHLO") {
				_, _ = serverPipe.Write([]byte("250-127.0.0.1\r\n250-STARTTLS\r\n250 HELP\r\n"))
			}
			stLine, _ := readRawLine(serverPipe)
			if strings.HasPrefix(strings.ToUpper(stLine), "STARTTLS") {
				_, _ = serverPipe.Write([]byte("220 2.0.0 Ready for TLS\r\n"))
			}
			tlsConn := tls.Server(serverPipe, &tls.Config{Certificates: []tls.Certificate{cert}})
			handleMockSMTPSession(tlsConn, false)
		}()
		return clientPipe, nil
	}

	err := alerter.SendTestEmail(context.Background())
	if err != nil {
		t.Fatalf("SendTestEmail over STARTTLS failed: %v", err)
	}
}

func TestAlerter_DefaultSendMail_Timeout(t *testing.T) {
	cfg := config.EmailConfig{
		Enabled:   true,
		SMTPHost:  "127.0.0.1",
		SMTPPort:  465,
		FromEmail: "a@b.com",
		ToEmail:   "c@d.com",
	}
	alerter := NewAlerter(cfg, nil)
	alerter.timeout = 50 * time.Millisecond
	alerter.dialer = func(ctx context.Context, addr string, isImplicit bool, clientTLS *tls.Config) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}

	err := alerter.SendTestEmail(context.Background())
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected timeout error, got %v", err)
	}
}

func TestAlerter_STARTTLS_Required_FailsFastIfMissing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		w := bufio.NewWriter(conn)
		_, _ = w.WriteString("220 mock.smtp Service Ready\r\n")
		_ = w.Flush()
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			upper := strings.ToUpper(strings.TrimSpace(line))
			if strings.HasPrefix(upper, "EHLO") || strings.HasPrefix(upper, "HELO") {
				_, _ = w.WriteString("250-mock.smtp Hello\r\n250 AUTH PLAIN\r\n")
				_ = w.Flush()
			} else if strings.HasPrefix(upper, "QUIT") {
				_, _ = w.WriteString("221 Bye\r\n")
				_ = w.Flush()
				return
			}
		}
	}()

	cfg := config.EmailConfig{
		Enabled:   true,
		SMTPHost:  "127.0.0.1",
		SMTPPort:  587,
		UseTLS:    true,
		Username:  "user",
		Password:  "pass",
		FromEmail: "from@example.com",
		ToEmail:   "to@example.com",
	}
	alerter := NewAlerter(cfg, nil)
	alerter.timeout = 2 * time.Second
	alerter.dialer = func(ctx context.Context, addr string, isImplicit bool, clientTLS *tls.Config) (net.Conn, error) {
		return net.Dial("tcp", ln.Addr().String())
	}
	err = alerter.SendTestEmail(context.Background())
	if err == nil {
		t.Fatal("expected failure when STARTTLS is required but not advertised")
	}
	if !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("expected error mentioning STARTTLS, got: %v", err)
	}
}

func TestAlerter_HeaderInjectionDisabledDedupAndLoginAuthTLS(t *testing.T) {
	ctx := context.Background()
	store, _ := db.NewSpoolStore(t.TempDir(), nil)

	// 1. Disabled alerter must NOT mark findings as already alerted
	disabled := NewAlerter(config.EmailConfig{Enabled: false}, store)
	scan := &models.ScanResult{
		Items: []models.ManagedItem{
			{
				Node:           "Axis",
				TargetType:     models.TargetDocker,
				Name:           "auth",
				CurrentVersion: "1.0",
				CritCount:      1,
				Vulnerabilities: []models.Vulnerability{
					{ID: "CVE-2026-0001", Severity: models.SeverityCritical},
				},
			},
		},
	}
	cnt, err := disabled.NotifyScanFindings(ctx, scan)
	if err != nil || cnt != 0 {
		t.Fatalf("expected 0 count and nil err when disabled, got cnt=%d err=%v", cnt, err)
	}
	sent, _ := store.HasAlertBeenSent(ctx, "Axis:cve:docker:auth:CVE-2026-0001")
	if sent {
		t.Fatal("disabled alerter must NOT record alert as sent")
	}

	// 2. Reject CRLF in email addresses and strip CRLF from Subject fields
	badCfgAlerter := NewAlerter(config.EmailConfig{
		Enabled:   true,
		SMTPHost:  "smtp.example.com",
		SMTPPort:  587,
		FromEmail: "from@example.com\r\nBcc: evil@attacker.com",
		ToEmail:   "to@example.com",
	}, store)
	if err := badCfgAlerter.SendTestEmail(ctx); err == nil {
		t.Fatal("expected error when FromEmail contains CRLF")
	}

	var capturedMsg string
	enabled := NewAlerter(config.EmailConfig{
		Enabled:   true,
		SMTPHost:  "smtp.example.com",
		SMTPPort:  587,
		FromEmail: "from@example.com",
		ToEmail:   "to@example.com",
	}, store)
	enabled.sendMailFunc = func(ctx context.Context, cfg config.EmailConfig, addr string, a smtp.Auth, from string, to []string, msg []byte) error {
		capturedMsg = string(msg)
		return nil
	}
	if err := enabled.NotifyDeadManRollback(ctx, "svc\r\nBcc: x@y.com", "1.0\nEvil: 1", "2.0", "reason"); err != nil {
		t.Fatal(err)
	}
	headers := strings.SplitN(capturedMsg, "\r\n\r\n", 2)[0]
	if strings.Contains(headers, "\nBcc:") || strings.Contains(headers, "\nEvil:") || strings.Contains(headers, "\rBcc:") {
		t.Fatalf("CRLF header injection created extra header line:\n%s", headers)
	}

	// 3. loginAuth rejects non-TLS connections
	la := &loginAuth{username: "u", password: "p", host: "smtp.example.com"}
	if _, _, err := la.Start(&smtp.ServerInfo{Name: "smtp.example.com", TLS: false}); err == nil {
		t.Fatal("expected loginAuth.Start to reject unencrypted TLS=false server")
	}
}
