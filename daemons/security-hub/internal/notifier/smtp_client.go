package notifier

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strings"

	"github.com/jaewoook/security-hub/internal/config"
)

type sendMailFunc func(ctx context.Context, cfg config.EmailConfig, addr string, a smtp.Auth, from string, to []string, msg []byte) error

type dialerFunc func(ctx context.Context, addr string, isImplicit bool, tlsConfig *tls.Config) (net.Conn, error)

func defaultDial(ctx context.Context, addr string, isImplicit bool, tlsConfig *tls.Config) (net.Conn, error) {
	if isImplicit {
		tlsDialer := &tls.Dialer{
			Config: tlsConfig,
		}
		return tlsDialer.DialContext(ctx, "tcp", addr)
	}
	netDialer := &net.Dialer{}
	return netDialer.DialContext(ctx, "tcp", addr)
}

type forcedTLSAuth struct {
	auth smtp.Auth
}

func (f forcedTLSAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	s := *server
	s.TLS = true
	return f.auth.Start(&s)
}

func (f forcedTLSAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	return f.auth.Next(fromServer, more)
}

type loginAuth struct {
	username string
	password string
	host     string
}

func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if !server.TLS {
		return "", nil, errors.New("unencrypted connection")
	}
	if server.Name != a.host {
		return "", nil, errors.New("wrong host name")
	}
	return "LOGIN", []byte(a.username), nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		return []byte(a.password), nil
	}
	return nil, nil
}

func sendMailWithDialer(ctx context.Context, dialer dialerFunc, cfg config.EmailConfig, addr string, a smtp.Auth, from string, to []string, msg []byte) error {
	host := cfg.SMTPHost
	isImplicit := cfg.SMTPPort == 465 || (cfg.UseTLS && cfg.SMTPPort != 587 && cfg.SMTPPort != 25 && cfg.SMTPPort != 2525 && cfg.SMTPPort != 2587)

	tlsConfig := &tls.Config{
		ServerName: host,
	}
	if host == "127.0.0.1" || host == "localhost" {
		tlsConfig.InsecureSkipVerify = true
	}

	if dialer == nil {
		dialer = defaultDial
	}

	conn, err := dialer(ctx, addr, isImplicit, tlsConfig)
	if err != nil {
		if isImplicit {
			return fmt.Errorf("tls dial failed for %s: %w", addr, err)
		}
		return fmt.Errorf("dial failed for %s: %w", addr, err)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("smtp handshake failed for %s: %w", addr, err)
	}
	defer client.Close()

	if !isImplicit && (cfg.UseTLS || cfg.SMTPPort == 587) {
		ok, _ := client.Extension("STARTTLS")
		if !ok {
			return fmt.Errorf("smtp server %s does not support required STARTTLS encryption", addr)
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("smtp starttls failed for %s: %w", addr, err)
		}
	}

	if a != nil {
		authToSend := a
		if isImplicit {
			authToSend = forcedTLSAuth{auth: a}
		}
		if ok, authMechanisms := client.Extension("AUTH"); ok {
			upper := strings.ToUpper(authMechanisms)
			if !strings.Contains(upper, "PLAIN") && strings.Contains(upper, "LOGIN") && cfg.Username != "" {
				authToSend = &loginAuth{
					username: cfg.Username,
					password: cfg.Password,
					host:     host,
				}
				if isImplicit {
					authToSend = forcedTLSAuth{auth: authToSend}
				}
			}
			if err := client.Auth(authToSend); err != nil {
				return fmt.Errorf("smtp auth failed: %w", err)
			}
		}
	}

	if err := client.Mail(from); err != nil {
		return fmt.Errorf("smtp mail from failed: %w", err)
	}
	for _, rcpt := range to {
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("smtp rcpt to failed for %s: %w", rcpt, err)
		}
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp data failed: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("smtp write message failed: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp close data writer failed: %w", err)
	}

	_ = client.Quit()
	return nil
}
