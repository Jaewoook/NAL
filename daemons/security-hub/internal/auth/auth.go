package auth

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/jaewoook/security-hub/internal/config"
	"github.com/jaewoook/security-hub/internal/fsutil"
	"github.com/jaewoook/security-hub/internal/httputil"
)

const (
	SessionCookieName   = "nal_security_hub_session"
	OIDCStateCookieName = "nal_oidc_state"
	OIDCNonceCookieName = "nal_oidc_nonce"
	CSRFCookieName      = "nal_csrf_token"
	CSRFHeaderName      = "X-CSRF-Token"

	maxPendingChallenges = 1024
	oidcHTTPTimeout      = 8 * time.Second
)

type SessionClaims struct {
	Subject   string `json:"sub"`
	Method    string `json:"method"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

type PasskeyCredential struct {
	CredentialID  string    `json:"credential_id"`
	Label         string    `json:"label"`
	PublicKeySPKI string    `json:"public_key_spki"`
	SignCount     uint32    `json:"sign_count"`
	CreatedAt     time.Time `json:"created_at"`
}

type persistedAuthState struct {
	Passkeys         []PasskeyCredential `json:"passkeys"`
	BreakGlassTokens map[string]int64    `json:"break_glass_tokens"`
}

type challengeEntry struct {
	ExpiresAt time.Time
	Kind      string
	Subject   string
}

type Manager struct {
	mu         sync.Mutex
	cfg        config.AuthConfig
	stateFile  string
	state      persistedAuthState
	challenges map[string]challengeEntry
	httpClient *http.Client

	oidcMu         sync.Mutex
	oidcDoc        *oidcDiscoveryDoc
	oidcDocIssuer  string
	oidcDocFetched time.Time
	jwksKeys       []jwkKey
	jwksURI        string
	jwksFetched    time.Time
}

func (m *Manager) SetHTTPClient(c *http.Client) {
	if c != nil {
		m.httpClient = c
	}
}

func NewManager(cfg config.AuthConfig, stateFilePath string) (*Manager, error) {
	if cfg.SessionSecret == "" ||
		cfg.SessionSecret == "default-dev-session-secret-change-in-prod" ||
		cfg.SessionSecret == "replace-with-openssl-rand-hex-32" {
		randBytes := make([]byte, 32)
		if _, err := rand.Read(randBytes); err != nil {
			return nil, fmt.Errorf("failed to generate session secret: %w", err)
		}
		cfg.SessionSecret = hex.EncodeToString(randBytes)
	}
	if stateFilePath != "" {
		if err := os.MkdirAll(filepath.Dir(stateFilePath), 0700); err != nil {
			return nil, err
		}
	}
	m := &Manager{
		cfg:        cfg,
		stateFile:  stateFilePath,
		challenges: make(map[string]challengeEntry),
		httpClient: httputil.NoRedirectClient(nil, oidcHTTPTimeout),
		state: persistedAuthState{
			BreakGlassTokens: make(map[string]int64),
		},
	}
	if stateFilePath != "" {
		if err := m.withFileLock(func() error {
			return m.loadStateFromDiskLocked()
		}); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func (m *Manager) withFileLock(fn func() error) error {
	if m.stateFile == "" {
		return fn()
	}
	lockPath := m.stateFile + ".lock"
	lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("failed to open auth lock %s: %w", lockPath, err)
	}
	defer lf.Close()
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("failed to lock auth state %s: %w", lockPath, err)
	}
	defer func() { _ = syscall.Flock(int(lf.Fd()), syscall.LOCK_UN) }()
	return fn()
}

func (m *Manager) loadStateFromDiskLocked() error {
	if m.stateFile == "" {
		return nil
	}
	raw, err := os.ReadFile(m.stateFile)
	if err != nil {
		if os.IsNotExist(err) {
			if m.state.BreakGlassTokens == nil {
				m.state.BreakGlassTokens = make(map[string]int64)
			}
			return nil
		}
		return fmt.Errorf("failed to read auth state %s: %w", m.stateFile, err)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		if m.state.BreakGlassTokens == nil {
			m.state.BreakGlassTokens = make(map[string]int64)
		}
		return nil
	}
	var loaded persistedAuthState
	if err := json.Unmarshal(raw, &loaded); err != nil {
		return fmt.Errorf("corrupt auth state file %s: %w", m.stateFile, err)
	}
	if loaded.BreakGlassTokens == nil {
		loaded.BreakGlassTokens = make(map[string]int64)
	}
	m.state = loaded
	return nil
}

func (m *Manager) saveStateLocked() error {
	if m.stateFile == "" {
		return nil
	}
	raw, err := json.MarshalIndent(m.state, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(m.stateFile, raw, 0600)
}

func (m *Manager) pruneExpiredBreakGlassTokensLocked() int {
	now := time.Now().UTC().Unix()
	pruned := 0
	for tok, exp := range m.state.BreakGlassTokens {
		if now > exp {
			delete(m.state.BreakGlassTokens, tok)
			pruned++
		}
	}
	return pruned
}

func (m *Manager) GenerateBreakGlassToken(ttl time.Duration) (string, error) {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(buf)
	m.mu.Lock()
	defer m.mu.Unlock()

	var genErr error
	err := m.withFileLock(func() error {
		if err := m.loadStateFromDiskLocked(); err != nil {
			return err
		}
		m.pruneExpiredBreakGlassTokensLocked()
		m.state.BreakGlassTokens[tok] = time.Now().UTC().Add(ttl).Unix()
		return m.saveStateLocked()
	})
	if err != nil {
		genErr = err
	}
	return tok, genErr
}

func (m *Manager) ConsumeBreakGlassToken(token string) (bool, error) {
	if token == "" {
		return false, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	var valid bool
	err := m.withFileLock(func() error {
		if err := m.loadStateFromDiskLocked(); err != nil {
			return err
		}
		exp, ok := m.state.BreakGlassTokens[token]
		if ok {
			delete(m.state.BreakGlassTokens, token)
		}
		pruned := m.pruneExpiredBreakGlassTokensLocked()
		if ok || pruned > 0 {
			if err := m.saveStateLocked(); err != nil {
				return err
			}
		}
		if !ok {
			valid = false
			return nil
		}
		if time.Now().UTC().Unix() > exp {
			valid = false
			return nil
		}
		valid = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return valid, nil
}

func (m *Manager) HasRegisteredPasskeys() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.state.Passkeys) > 0
}
