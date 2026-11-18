package auth

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jaewoook/security-hub/internal/config"
)

const (
	SessionCookieName   = "nal_security_hub_session"
	OIDCStateCookieName = "nal_oidc_state"
	OIDCNonceCookieName = "nal_oidc_nonce"
	CSRFCookieName      = "nal_csrf_token"
	CSRFHeaderName      = "X-CSRF-Token"

	maxPendingChallenges = 1024
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

func WriteJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (m *Manager) SetHTTPClient(c *http.Client) {
	if c != nil {
		m.httpClient = c
	}
}

func (m *Manager) safeHTTPClient() *http.Client {
	var c http.Client
	if m.httpClient != nil {
		c = *m.httpClient
	}
	if c.Timeout <= 0 {
		c.Timeout = 8 * time.Second
	}
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &c
}

func (m *Manager) isSecureCookie() bool {
	return strings.HasPrefix(strings.ToLower(m.cfg.RedirectURL), "https://") ||
		strings.HasPrefix(strings.ToLower(m.cfg.PublicURL), "https://")
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
		httpClient: &http.Client{
			Timeout: 8 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
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

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmpFile, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp.*")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Chmod(perm); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	cleanup = false
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
	return writeFileAtomic(m.stateFile, raw, 0600)
}

func (m *Manager) signPayload(payload string) string {
	secret := m.cfg.SessionSecret
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (m *Manager) csrfTokenForCookie(sessionVal string) string {
	return m.signPayload("csrf." + sessionVal)
}

func (m *Manager) CSRFTokenForRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	c, err := r.Cookie(SessionCookieName)
	if err != nil || c.Value == "" {
		return ""
	}
	return m.csrfTokenForCookie(c.Value)
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
	secure := m.isSecureCookie()

	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    val,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
		Expires:  exp,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCookieName,
		Value:    m.csrfTokenForCookie(val),
		Path:     "/",
		HttpOnly: false,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
		Expires:  exp,
	})
	return nil
}

func (m *Manager) ClearSessionCookie(w http.ResponseWriter) {
	secure := m.isSecureCookie()
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
		MaxAge:   -1,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: false,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
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

func (m *Manager) isAllowedOriginHost(rawOrigin string, reqHost string) bool {
	u, err := url.Parse(rawOrigin)
	if err != nil || u.Host == "" {
		return false
	}
	if !strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https") {
		return false
	}
	if m.isSecureCookie() && !strings.EqualFold(u.Scheme, "https") {
		return false
	}
	if reqHost != "" && strings.EqualFold(u.Host, reqHost) {
		return true
	}
	for _, pub := range []string{m.cfg.PublicURL, m.cfg.RedirectURL} {
		if pub == "" {
			continue
		}
		if pu, pErr := url.Parse(pub); pErr == nil && pu.Host != "" && strings.EqualFold(u.Host, pu.Host) {
			if strings.EqualFold(u.Scheme, pu.Scheme) {
				return true
			}
		}
	}
	return false
}

func (m *Manager) VerifyOriginAndFetchSite(r *http.Request) error {
	if sfs := strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")); sfs != "" {
		if sfs != "same-origin" {
			return fmt.Errorf("cross-site request blocked (Sec-Fetch-Site=%q)", sfs)
		}
	}
	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
		if !m.isAllowedOriginHost(origin, r.Host) {
			return fmt.Errorf("origin %q not permitted", origin)
		}
	} else if ref := strings.TrimSpace(r.Header.Get("Referer")); ref != "" {
		if !m.isAllowedOriginHost(ref, r.Host) {
			return fmt.Errorf("referer %q not permitted", ref)
		}
	}
	return nil
}

func (m *Manager) VerifyCSRF(r *http.Request) error {
	if err := m.VerifyOriginAndFetchSite(r); err != nil {
		return err
	}
	c, err := r.Cookie(SessionCookieName)
	if err != nil || c.Value == "" {
		return errors.New("missing session cookie")
	}
	got := r.Header.Get(CSRFHeaderName)
	if got == "" {
		return errors.New("missing X-CSRF-Token header")
	}
	expected := m.csrfTokenForCookie(c.Value)
	if !hmac.Equal([]byte(got), []byte(expected)) {
		return errors.New("invalid CSRF token")
	}
	return nil
}

func (m *Manager) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := m.VerifyRequest(r); err != nil {
			WriteJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r)
	}
}

func (m *Manager) RequireAuthCSRF(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := m.VerifyRequest(r); err != nil {
			WriteJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			if err := m.VerifyCSRF(r); err != nil {
				WriteJSONError(w, http.StatusForbidden, "csrf validation failed")
				return
			}
		}
		next(w, r)
	}
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

func (m *Manager) StartOIDCLogin(w http.ResponseWriter, r *http.Request) {
	if m.cfg.OIDCIssuer == "" {
		http.Error(w, "OIDC issuer is not configured", http.StatusServiceUnavailable)
		return
	}
	issURL, err := validateHTTPSURL(m.cfg.OIDCIssuer)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid OIDC issuer configuration: %v", err), http.StatusServiceUnavailable)
		return
	}

	authURL, _, _ := m.oidcFallbackEndpoints(issURL.String())
	discCtx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	doc, dErr := m.discoverOIDC(discCtx)
	cancel()
	if dErr == nil && doc.AuthorizationEndpoint != "" {
		authURL = doc.AuthorizationEndpoint
	}

	stateBytes := make([]byte, 16)
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		http.Error(w, "failed to generate OAuth state", http.StatusInternalServerError)
		return
	}
	if _, err := rand.Read(nonceBytes); err != nil {
		http.Error(w, "failed to generate OIDC nonce", http.StatusInternalServerError)
		return
	}
	state := hex.EncodeToString(stateBytes)
	nonce := hex.EncodeToString(nonceBytes)

	http.SetCookie(w, &http.Cookie{
		Name:     OIDCStateCookieName,
		Value:    state,
		Path:     "/api/auth/oidc/callback",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   m.isSecureCookie(),
		MaxAge:   300,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     OIDCNonceCookieName,
		Value:    nonce,
		Path:     "/api/auth/oidc/callback",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   m.isSecureCookie(),
		MaxAge:   300,
	})

	q := url.Values{}
	q.Set("client_id", m.cfg.OIDCClientID)
	q.Set("response_type", "code")
	q.Set("scope", "openid profile email")
	q.Set("redirect_uri", m.cfg.RedirectURL)
	q.Set("state", state)
	q.Set("nonce", nonce)
	http.Redirect(w, r, authURL+"?"+q.Encode(), http.StatusFound)
}

func clearOIDCCallbackCookies(w http.ResponseWriter, secure bool) {
	for _, name := range []string{OIDCStateCookieName, OIDCNonceCookieName} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/api/auth/oidc/callback",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   secure,
			MaxAge:   -1,
		})
	}
}

func (m *Manager) HandleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	issURL, issErr := validateHTTPSURL(m.cfg.OIDCIssuer)
	if issErr != nil {
		http.Error(w, "invalid OIDC issuer configuration", http.StatusServiceUnavailable)
		return
	}

	state := r.URL.Query().Get("state")
	stateCookie, err := r.Cookie(OIDCStateCookieName)
	nonceCookie, nonceErr := r.Cookie(OIDCNonceCookieName)
	clearOIDCCallbackCookies(w, m.isSecureCookie())
	if err != nil || state == "" || stateCookie.Value == "" || !hmac.Equal([]byte(stateCookie.Value), []byte(state)) {
		http.Error(w, "invalid or missing OAuth state parameter (CSRF detected)", http.StatusBadRequest)
		return
	}
	if nonceErr != nil || nonceCookie.Value == "" {
		http.Error(w, "missing OIDC nonce cookie", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing authorization code", http.StatusBadRequest)
		return
	}

	_, tokenURL, _ := m.oidcFallbackEndpoints(issURL.String())
	if doc, dErr := m.discoverOIDC(r.Context()); dErr == nil && doc.TokenEndpoint != "" {
		tokenURL = doc.TokenEndpoint
	}
	if _, err := validateHTTPSURL(tokenURL); err != nil {
		http.Error(w, "insecure OIDC token endpoint", http.StatusBadGateway)
		return
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", m.cfg.OIDCClientID)
	form.Set("client_secret", m.cfg.OIDCClientSecret)
	form.Set("redirect_uri", m.cfg.RedirectURL)

	resp, err := m.safeHTTPClient().PostForm(tokenURL, form)
	if err != nil {
		http.Error(w, fmt.Sprintf("OIDC token exchange failed: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		http.Error(w, fmt.Sprintf("OIDC token endpoint returned HTTP %d", resp.StatusCode), http.StatusBadGateway)
		return
	}

	var tokResp struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tokResp); err != nil || tokResp.IDToken == "" {
		http.Error(w, "invalid OIDC token response", http.StatusBadGateway)
		return
	}

	subject, err := m.verifyAndExtractIDToken(r.Context(), tokResp.IDToken, nonceCookie.Value)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid OIDC ID token: %v", err), http.StatusUnauthorized)
		return
	}
	if subject == "" {
		subject = "nal-admin"
	}
	if err := m.IssueSessionCookie(w, subject, "sso"); err != nil {
		http.Error(w, "failed to issue session cookie", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

type idTokenClaims struct {
	Iss               string `json:"iss"`
	Aud               any    `json:"aud"`
	Azp               string `json:"azp"`
	Nonce             string `json:"nonce"`
	Exp               int64  `json:"exp"`
	Nbf               int64  `json:"nbf"`
	PreferredUsername string `json:"preferred_username"`
	Nickname          string `json:"nickname"`
	Name              string `json:"name"`
	Email             string `json:"email"`
	Sub               string `json:"sub"`
}

func extractUsernameFromClaims(claims idTokenClaims) string {
	if claims.PreferredUsername != "" {
		return claims.PreferredUsername
	}
	if claims.Nickname != "" {
		return claims.Nickname
	}
	if claims.Email != "" {
		parts := strings.Split(claims.Email, "@")
		return parts[0]
	}
	if claims.Name != "" {
		return claims.Name
	}
	return claims.Sub
}

func (m *Manager) verifyAndExtractIDToken(ctx context.Context, jwt string, expectedNonce string) (string, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return "", errors.New("malformed JWT: expected 3 segments")
	}
	if err := m.verifyJWTSignature(ctx, parts[0], parts[1], parts[2]); err != nil {
		return "", err
	}

	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("failed to decode JWT payload: %w", err)
	}
	var claims idTokenClaims
	if err := json.Unmarshal(raw, &claims); err != nil {
		return "", fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	now := time.Now().UTC().Unix()
	if claims.Exp <= 0 {
		return "", errors.New("ID token missing exp claim")
	}
	if now > (claims.Exp + 60) {
		return "", errors.New("ID token is expired")
	}
	if claims.Nbf > 0 && now < (claims.Nbf-60) {
		return "", errors.New("ID token not yet valid (nbf)")
	}

	if m.cfg.OIDCIssuer != "" {
		if claims.Iss == "" {
			return "", errors.New("ID token missing iss claim")
		}
		expURL, err1 := validateHTTPSURL(m.cfg.OIDCIssuer)
		actURL, err2 := validateHTTPSURL(claims.Iss)
		if err1 != nil || err2 != nil ||
			!strings.EqualFold(expURL.Scheme, actURL.Scheme) ||
			!strings.EqualFold(expURL.Host, actURL.Host) ||
			normalizeIssuerPath(expURL.Path) != normalizeIssuerPath(actURL.Path) {
			return "", fmt.Errorf("issuer mismatch: expected %q, got %q", m.cfg.OIDCIssuer, claims.Iss)
		}
	}

	if expectedNonce != "" {
		if claims.Nonce == "" || !hmac.Equal([]byte(claims.Nonce), []byte(expectedNonce)) {
			return "", errors.New("ID token nonce mismatch")
		}
	}

	if m.cfg.OIDCClientID != "" {
		if claims.Aud == nil {
			return "", errors.New("ID token missing aud claim")
		}
		var audMatched bool
		var audMulti bool
		switch a := claims.Aud.(type) {
		case string:
			audMatched = (a == m.cfg.OIDCClientID)
		case []any:
			audMulti = len(a) > 1
			for _, item := range a {
				if s, ok := item.(string); ok && s == m.cfg.OIDCClientID {
					audMatched = true
					break
				}
			}
		}
		if !audMatched {
			return "", fmt.Errorf("audience mismatch: token does not match client ID %q", m.cfg.OIDCClientID)
		}
		if audMulti {
			if claims.Azp == "" || claims.Azp != m.cfg.OIDCClientID {
				return "", fmt.Errorf("authorized party (azp) mismatch for multi-audience token: got %q, want %q", claims.Azp, m.cfg.OIDCClientID)
			}
		} else if claims.Azp != "" && claims.Azp != m.cfg.OIDCClientID {
			return "", fmt.Errorf("authorized party (azp) mismatch: got %q, want %q", claims.Azp, m.cfg.OIDCClientID)
		}
	}

	return extractUsernameFromClaims(claims), nil
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
	var claims idTokenClaims
	if err := json.Unmarshal(raw, &claims); err != nil {
		return ""
	}
	return extractUsernameFromClaims(claims)
}
