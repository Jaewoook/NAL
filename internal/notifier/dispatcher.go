package notifier

import (
	"fmt"
	"sync"

	"github.com/jaewoook/server-monitor/internal/config"
	"github.com/jaewoook/server-monitor/internal/models"
)

// Dispatcher coordinates fan-out of alerts across all registered notification channels.
type Dispatcher struct {
	mu       sync.RWMutex
	channels []Channel
}

// NewDispatcher creates a new Dispatcher with optional initial channels.
func NewDispatcher(channels ...Channel) *Dispatcher {
	d := &Dispatcher{
		channels: make([]Channel, 0, len(channels)),
	}
	for _, ch := range channels {
		if ch != nil {
			d.channels = append(d.channels, ch)
		}
	}
	return d
}

// NewDispatcherFromConfig creates and populates a Dispatcher based on active notification configurations.
func NewDispatcherFromConfig(cfg *config.NotificationsConfig) *Dispatcher {
	d := NewDispatcher()
	if cfg == nil {
		return d
	}

	if cfg.Telegram.Enabled {
		d.Register(NewTelegramChannel(cfg.Telegram.BotToken, cfg.Telegram.ChatID))
	}
	if cfg.Discord.Enabled {
		d.Register(NewDiscordChannel(cfg.Discord.WebhookURL))
	}
	if cfg.Slack.Enabled {
		d.Register(NewSlackChannel(cfg.Slack.WebhookURL))
	}
	if cfg.Email.Enabled {
		d.Register(NewEmailChannel(cfg.Email))
	}
	if cfg.Webhook.Enabled {
		d.Register(NewWebhookChannel(cfg.Webhook.URL))
	}

	return d
}

// Register adds a channel to the dispatcher.
func (d *Dispatcher) Register(channel Channel) {
	if channel == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.channels = append(d.channels, channel)
}

// Channels returns a shallow copy of all registered channels.
func (d *Dispatcher) Channels() []Channel {
	d.mu.RLock()
	defer d.mu.RUnlock()
	copied := make([]Channel, len(d.channels))
	copy(copied, d.channels)
	return copied
}

// Dispatch broadcasts an alert concurrently across all registered channels.
// It returns a map of channel names to errors for any channels that failed.
func (d *Dispatcher) Dispatch(alert *models.Alert) map[string]error {
	d.mu.RLock()
	channels := make([]Channel, len(d.channels))
	copy(channels, d.channels)
	d.mu.RUnlock()

	if len(channels) == 0 || alert == nil {
		return make(map[string]error)
	}

	type channelResult struct {
		name string
		err  error
	}

	resChan := make(chan channelResult, len(channels))
	var wg sync.WaitGroup

	for _, ch := range channels {
		wg.Add(1)
		go func(c Channel) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					resChan <- channelResult{
						name: c.Name(),
						err:  fmt.Errorf("channel panic recovered: %v", r),
					}
				}
			}()

			err := c.Send(alert)
			resChan <- channelResult{
				name: c.Name(),
				err:  err,
			}
		}(ch)
	}

	wg.Wait()
	close(resChan)

	errorsMap := make(map[string]error)
	for res := range resChan {
		if res.err != nil {
			errorsMap[res.name] = res.err
		}
	}

	return errorsMap
}
