package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func WriteJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (m *Manager) isSecureCookie() bool {
	return strings.HasPrefix(strings.ToLower(m.cfg.RedirectURL), "https://") ||
		strings.HasPrefix(strings.ToLower(m.cfg.PublicURL), "https://")
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
