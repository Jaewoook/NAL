package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jaewoook/security-hub/internal/config"
)

const SessionCookieName = "nal_security_hub_session"

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
	CreatedAt     time.Time `json:"created_at"`
}

type persistedAuthState struct {
	Passkeys         []PasskeyCredential `json:"passkeys"`
	BreakGlassTokens map[string]int64    `json:"break_glass_tokens"`
}

type Manager struct {
	mu         sync.Mutex
	cfg        config.AuthConfig
	stateFile  string
	state      persistedAuthState
	challenges map[string]time.Time
	httpClient *http.Client
}

func NewManager(cfg config.AuthConfig, stateFilePath string) (*Manager, error) {
	if stateFilePath != "" {
		if err := os.MkdirAll(filepath.Dir(stateFilePath), 0755); err != nil {
			return nil, err
		}
	}
	m := &Manager{
		cfg:        cfg,
		stateFile:  stateFilePath,
		challenges: make(map[string]time.Time),
		httpClient: &http.Client{Timeout: 8 * time.Second},
		state: persistedAuthState{
			BreakGlassTokens: make(map[string]int64),
		},
	}
	if stateFilePath != "" {
		if raw, err := os.ReadFile(stateFilePath); err == nil {
			_ = json.Unmarshal(raw, &m.state)
			if m.state.BreakGlassTokens == nil {
				m.state.BreakGlassTokens = make(map[string]int64)
			}
		}
	}
	return m, nil
}

func (m *Manager) saveStateLocked() error {
	if m.stateFile == "" {
		return nil
	}
	raw, err := json.MarshalIndent(m.state, "", "  ")
	if err != nil {
		return err
	}
	tmp := m.stateFile + ".tmp"
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, m.stateFile)
}

func (m *Manager) signPayload(payloadB64 string) string {
	secret := m.cfg.SessionSecret
	if secret == "" {
		secret = "default-dev-session-secret-change-in-prod"
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payloadB64))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (m *Manager) IssueSessionCookie(w http.ResponseWriter, subject, method string) error {
	ttl := m.cfg.SessionTTLHours
	if ttl <= 0 {
		ttl = 24
	}
	now := time.Now().UTC()
	exp := now.Add(time.Duration(ttl) * time.Hour)
	claims := SessionClaims{
		Subject:   subject,
		Method:    method,
		IssuedAt:  now.Unix(),
		ExpiresAt: exp.Unix(),
	}
	raw, err := json.Marshal(claims)
	if err != nil {
		return err
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(raw)
	sig := m.signPayload(payloadB64)
	val := payloadB64 + "." + sig

	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    val,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  exp,
	})
	return nil
}

func (m *Manager) ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
}

func (m *Manager) VerifyRequest(r *http.Request) (*SessionClaims, error) {
	c, err := r.Cookie(SessionCookieName)
	if err != nil || c.Value == "" {
		return nil, errors.New("missing session cookie")
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 2 {
		return nil, errors.New("malformed session cookie")
	}
	expectedSig := m.signPayload(parts[0])
	if !hmac.Equal([]byte(parts[1]), []byte(expectedSig)) {
		return nil, errors.New("invalid session signature")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	var claims SessionClaims
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, err
	}
	if time.Now().UTC().Unix() > claims.ExpiresAt {
		return nil, errors.New("session expired")
	}
	return &claims, nil
}

func (m *Manager) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := m.VerifyRequest(r); err != nil {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
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
	m.state.BreakGlassTokens[tok] = time.Now().UTC().Add(ttl).Unix()
	err := m.saveStateLocked()
	m.mu.Unlock()
	return tok, err
}

func (m *Manager) ConsumeBreakGlassToken(token string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Reload from disk in case CLI generated token in another process
	if m.stateFile != "" {
		if raw, err := os.ReadFile(m.stateFile); err == nil {
			_ = json.Unmarshal(raw, &m.state)
			if m.state.BreakGlassTokens == nil {
				m.state.BreakGlassTokens = make(map[string]int64)
			}
		}
	}
	exp, ok := m.state.BreakGlassTokens[token]
	if !ok {
		return false, nil
	}
	delete(m.state.BreakGlassTokens, token)
	_ = m.saveStateLocked()
	if time.Now().UTC().Unix() > exp {
		return false, nil
	}
	return true, nil
}

func (m *Manager) HasRegisteredPasskeys() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.state.Passkeys) > 0
}

func (m *Manager) StartOIDCLogin(w http.ResponseWriter, r *http.Request) {
	if m.cfg.OIDCIssuer == "" {
		http.Error(w, "OIDC issuer is not configured", http.StatusServiceUnavailable)
		return
	}
	issuer := strings.TrimRight(m.cfg.OIDCIssuer, "/")
	authURL := issuer + "/authorize/"
	if strings.Contains(issuer, "/application/o/") {
		parts := strings.Split(issuer, "/application/o/")
		authURL = parts[0] + "/application/o/authorize/"
	}
	q := url.Values{}
	q.Set("client_id", m.cfg.OIDCClientID)
	q.Set("response_type", "code")
	q.Set("scope", "openid profile email")
	q.Set("redirect_uri", m.cfg.RedirectURL)
	http.Redirect(w, r, authURL+"?"+q.Encode(), http.StatusFound)
}

func (m *Manager) HandleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing authorization code", http.StatusBadRequest)
		return
	}
	issuer := strings.TrimRight(m.cfg.OIDCIssuer, "/")
	tokenURL := issuer + "/token/"
	if strings.Contains(issuer, "/application/o/") {
		parts := strings.Split(issuer, "/application/o/")
		tokenURL = parts[0] + "/application/o/token/"
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", m.cfg.OIDCClientID)
	form.Set("client_secret", m.cfg.OIDCClientSecret)
	form.Set("redirect_uri", m.cfg.RedirectURL)

	resp, err := m.httpClient.PostForm(tokenURL, form)
	if err != nil {
		http.Error(w, fmt.Sprintf("OIDC token exchange failed: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	var tokResp struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokResp); err != nil || tokResp.IDToken == "" {
		http.Error(w, "invalid OIDC token response", http.StatusBadGateway)
		return
	}

	subject := extractUsernameFromJWT(tokResp.IDToken)
	if subject == "" {
		subject = "nal-admin"
	}
	_ = m.IssueSessionCookie(w, subject, "sso")
	http.Redirect(w, r, "/", http.StatusFound)
}

func extractUsernameFromJWT(jwt string) string {
	parts := strings.Split(jwt, ".")
	if len(parts) < 2 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var payload struct {
		PreferredUsername string `json:"preferred_username"`
		Nickname          string `json:"nickname"`
		Name              string `json:"name"`
		Email             string `json:"email"`
		Sub               string `json:"sub"`
	}
	_ = json.Unmarshal(raw, &payload)
	if payload.PreferredUsername != "" {
		return payload.PreferredUsername
	}
	if payload.Nickname != "" {
		return payload.Nickname
	}
	if payload.Email != "" {
		parts := strings.Split(payload.Email, "@")
		return parts[0]
	}
	if payload.Name != "" {
		return payload.Name
	}
	return payload.Sub
}
