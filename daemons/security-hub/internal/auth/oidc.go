package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jaewoook/security-hub/internal/httputil"
)

type oidcDiscoveryDoc struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

func validateHTTPSURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("URL is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid URL %q: %w", raw, err)
	}
	if !strings.EqualFold(u.Scheme, "https") || u.Host == "" {
		return nil, fmt.Errorf("URL %q must use https:// scheme", raw)
	}
	return u, nil
}

func normalizeIssuerPath(p string) string {
	return strings.TrimRight(p, "/")
}

func (m *Manager) oidcFallbackEndpoints(issuer string) (authURL, tokenURL, jwksURL string) {
	trimmed := strings.TrimRight(issuer, "/")
	authURL = trimmed + "/authorize/"
	tokenURL = trimmed + "/token/"
	jwksURL = trimmed + "/jwks/"
	if strings.Contains(trimmed, "/application/o/") {
		parts := strings.Split(trimmed, "/application/o/")
		authURL = parts[0] + "/application/o/authorize/"
		tokenURL = parts[0] + "/application/o/token/"
		// Authentik exposes per-application JWKS at <issuer>/jwks/
		jwksURL = trimmed + "/jwks/"
	}
	return authURL, tokenURL, jwksURL
}

func (m *Manager) discoverOIDC(ctx context.Context) (oidcDiscoveryDoc, error) {
	issURL, err := validateHTTPSURL(m.cfg.OIDCIssuer)
	if err != nil {
		return oidcDiscoveryDoc{}, err
	}

	m.oidcMu.Lock()
	if m.oidcDoc != nil && time.Since(m.oidcDocFetched) < 10*time.Minute && m.oidcDocIssuer == m.cfg.OIDCIssuer {
		doc := *m.oidcDoc
		m.oidcMu.Unlock()
		return doc, nil
	}
	m.oidcMu.Unlock()

	wellKnown := strings.TrimRight(issURL.String(), "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return oidcDiscoveryDoc{}, err
	}
	resp, err := httputil.NoRedirectClient(m.httpClient, oidcHTTPTimeout).Do(req)
	if err != nil {
		return oidcDiscoveryDoc{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return oidcDiscoveryDoc{}, fmt.Errorf("OIDC discovery returned HTTP %d", resp.StatusCode)
	}
	var doc oidcDiscoveryDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return oidcDiscoveryDoc{}, err
	}
	if doc.AuthorizationEndpoint != "" {
		if _, err := validateHTTPSURL(doc.AuthorizationEndpoint); err != nil {
			return oidcDiscoveryDoc{}, err
		}
	}
	if doc.TokenEndpoint != "" {
		if _, err := validateHTTPSURL(doc.TokenEndpoint); err != nil {
			return oidcDiscoveryDoc{}, err
		}
	}
	if doc.JWKSURI != "" {
		if _, err := validateHTTPSURL(doc.JWKSURI); err != nil {
			return oidcDiscoveryDoc{}, err
		}
	}

	m.oidcMu.Lock()
	m.oidcDoc = &doc
	m.oidcDocIssuer = m.cfg.OIDCIssuer
	m.oidcDocFetched = time.Now()
	m.oidcMu.Unlock()
	return doc, nil
}

func (m *Manager) fetchJWKS(ctx context.Context, jwksURI string, forceRefresh bool) ([]jwkKey, error) {
	if _, err := validateHTTPSURL(jwksURI); err != nil {
		return nil, err
	}
	m.oidcMu.Lock()
	if !forceRefresh && len(m.jwksKeys) > 0 && time.Since(m.jwksFetched) < 10*time.Minute && m.jwksURI == jwksURI {
		keys := append([]jwkKey(nil), m.jwksKeys...)
		m.oidcMu.Unlock()
		return keys, nil
	}
	m.oidcMu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, err
	}
	resp, err := httputil.NoRedirectClient(m.httpClient, oidcHTTPTimeout).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned HTTP %d", resp.StatusCode)
	}
	var payload struct {
		Keys []jwkKey `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&payload); err != nil {
		return nil, err
	}
	if len(payload.Keys) == 0 {
		return nil, errors.New("JWKS endpoint returned zero keys")
	}

	m.oidcMu.Lock()
	m.jwksKeys = payload.Keys
	m.jwksURI = jwksURI
	m.jwksFetched = time.Now()
	m.oidcMu.Unlock()
	return payload.Keys, nil
}

func (m *Manager) resolveJWKSURI(ctx context.Context) (string, error) {
	if doc, err := m.discoverOIDC(ctx); err == nil && doc.JWKSURI != "" {
		return doc.JWKSURI, nil
	}
	_, _, fallbackJWKS := m.oidcFallbackEndpoints(m.cfg.OIDCIssuer)
	if _, err := validateHTTPSURL(fallbackJWKS); err != nil {
		return "", err
	}
	return fallbackJWKS, nil
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

	resp, err := httputil.NoRedirectClient(m.httpClient, oidcHTTPTimeout).PostForm(tokenURL, form)
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
