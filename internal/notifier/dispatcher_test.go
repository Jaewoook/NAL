package notifier

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jaewoook/server-monitor/internal/config"
	"github.com/jaewoook/server-monitor/internal/models"
)

type mockChannel struct {
	name      string
	sendErr   error
	delay     time.Duration
	sentCount int
	mu        sync.Mutex
}

func (m *mockChannel) Name() string {
	return m.name
}

func (m *mockChannel) Send(alert *models.Alert) error {
	m.mu.Lock()
	m.sentCount++
	m.mu.Unlock()
	if m.delay > 0 {
		time.Sleep(m.delay)
	}
	return m.sendErr
}

func TestDispatcherDispatchSuccess(t *testing.T) {
	ch1 := &mockChannel{name: "ch1"}
	ch2 := &mockChannel{name: "ch2"}

	d := NewDispatcher(ch1, ch2)
	alert := &models.Alert{
		Title:   "Test Alert",
		Message: "Everything is fine",
		Level:   models.AlertLevelInfo,
	}

	errs := d.Dispatch(alert)
	if len(errs) != 0 {
		t.Fatalf("expected 0 errors, got: %v", errs)
	}

	if ch1.sentCount != 1 || ch2.sentCount != 1 {
		t.Errorf("expected both channels to be called once, got ch1=%d, ch2=%d", ch1.sentCount, ch2.sentCount)
	}
}

func TestDispatcherDispatchPartialFailure(t *testing.T) {
	ch1 := &mockChannel{name: "ch1"}
	ch2 := &mockChannel{name: "ch2", sendErr: errors.New("network failure")}

	d := NewDispatcher(ch1, ch2)
	alert := &models.Alert{
		Title:   "Test Alert",
		Message: "Critical issue",
		Level:   models.AlertLevelCritical,
	}

	errs := d.Dispatch(alert)
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %d: %v", len(errs), errs)
	}

	if err, ok := errs["ch2"]; !ok || err.Error() != "network failure" {
		t.Errorf("expected ch2 to report 'network failure', got: %v", err)
	}

	if ch1.sentCount != 1 || ch2.sentCount != 1 {
		t.Errorf("expected both channels to be called, got ch1=%d, ch2=%d", ch1.sentCount, ch2.sentCount)
	}
}

func TestDispatcherEmptyChannels(t *testing.T) {
	d := NewDispatcher()
	alert := &models.Alert{
		Title: "Test",
	}

	errs := d.Dispatch(alert)
	if len(errs) != 0 {
		t.Fatalf("expected empty error map when no channels registered, got: %v", errs)
	}
}

func TestDispatcherRegisterAndChannels(t *testing.T) {
	d := NewDispatcher()
	ch1 := &mockChannel{name: "ch1"}
	d.Register(ch1)

	channels := d.Channels()
	if len(channels) != 1 {
		t.Fatalf("expected 1 channel, got %d", len(channels))
	}
	if channels[0].Name() != "ch1" {
		t.Errorf("expected channel name 'ch1', got '%s'", channels[0].Name())
	}
}

func TestDispatcherNewFromConfig(t *testing.T) {
	cfg := &config.NotificationsConfig{
		Telegram: config.TelegramConfig{
			Enabled:  true,
			BotToken: "token123",
			ChatID:   "chat456",
		},
		Discord: config.DiscordConfig{
			Enabled:    true,
			WebhookURL: "http://example.com/discord",
		},
		Slack: config.SlackConfig{
			Enabled:    true,
			WebhookURL: "http://example.com/slack",
		},
		Email: config.EmailConfig{
			Enabled:  true,
			SMTPHost: "smtp.example.com",
			SMTPPort: 587,
			ToEmail:  "admin@example.com",
		},
		Webhook: config.WebhookConfig{
			Enabled: true,
			URL:     "http://example.com/webhook",
		},
	}

	d := NewDispatcherFromConfig(cfg)
	channels := d.Channels()
	if len(channels) != 5 {
		t.Fatalf("expected 5 channels configured, got %d", len(channels))
	}

	names := make(map[string]bool)
	for _, ch := range channels {
		names[ch.Name()] = true
	}

	expectedNames := []string{"telegram", "discord", "slack", "email", "webhook"}
	for _, expected := range expectedNames {
		if !names[expected] {
			t.Errorf("expected channel '%s' to be registered", expected)
		}
	}
}

type panicChannel struct {
	name string
}

func (p *panicChannel) Name() string {
	return p.name
}

func (p *panicChannel) Send(alert *models.Alert) error {
	panic("unexpected fatal crash in channel")
}

func TestDispatcherPanicRecovery(t *testing.T) {
	goodCh := &mockChannel{name: "good"}
	badCh := &panicChannel{name: "panicky"}

	d := NewDispatcher(goodCh, badCh)
	alert := &models.Alert{Title: "Crash Test"}

	errs := d.Dispatch(alert)
	if len(errs) != 1 {
		t.Fatalf("expected 1 error from panic channel, got %d", len(errs))
	}
	if err, ok := errs["panicky"]; !ok || !strings.Contains(err.Error(), "channel panic recovered") {
		t.Errorf("expected panic recovery error for panicky, got: %v", err)
	}
	if goodCh.sentCount != 1 {
		t.Errorf("expected good channel to complete despite other channel panicking, got sentCount=%d", goodCh.sentCount)
	}
}

func TestDispatcherNilAlertAndNilConfig(t *testing.T) {
	d := NewDispatcher(&mockChannel{name: "ch"})
	errs := d.Dispatch(nil)
	if len(errs) != 0 {
		t.Errorf("expected empty errors for nil alert, got %v", errs)
	}

	dNil := NewDispatcherFromConfig(nil)
	if len(dNil.Channels()) != 0 {
		t.Errorf("expected 0 channels from nil config, got %d", len(dNil.Channels()))
	}
}
