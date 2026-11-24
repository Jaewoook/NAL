package web

import (
	"net/http"
	"strings"

	"github.com/jaewoook/security-hub/internal/auth"
)

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	oidcConfigured := s.cfg != nil && s.cfg.Auth.OIDCIssuer != ""
	hasPasskeys := s.authMgr != nil && s.authMgr.HasRegisteredPasskeys()
	if s.authMgr == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"authenticated":   false,
			"oidc_configured": oidcConfigured,
			"has_passkeys":    hasPasskeys,
		})
		return
	}
	claims, err := s.authMgr.VerifyRequest(r)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"authenticated":   false,
			"oidc_configured": oidcConfigured,
			"has_passkeys":    hasPasskeys,
		})
		return
	}
	username := claims.Subject
	if atIdx := strings.Index(username, "@"); atIdx != -1 {
		username = username[:atIdx]
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated":   true,
		"subject":         claims.Subject,
		"username":        username,
		"method":          claims.Method,
		"has_passkeys":    hasPasskeys,
		"oidc_configured": oidcConfigured,
		"csrf_token":      s.authMgr.CSRFTokenForRequest(r),
	})
}

func (s *Server) handleTokenLogin(w http.ResponseWriter, r *http.Request) {
	if s.authMgr == nil {
		auth.WriteJSONError(w, http.StatusServiceUnavailable, "authentication manager is not configured")
		return
	}
	tok := r.URL.Query().Get("token")
	ok, err := s.authMgr.ConsumeBreakGlassToken(tok)
	if err != nil || !ok {
		http.Error(w, "Invalid or expired break-glass login token", http.StatusUnauthorized)
		return
	}
	if err := s.authMgr.IssueSessionCookie(w, "cli-break-glass-admin", "cli"); err != nil {
		http.Error(w, "Failed to issue session cookie", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		auth.WriteJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.authMgr != nil {
		if _, err := s.authMgr.VerifyRequest(r); err == nil {
			if err := s.authMgr.VerifyCSRF(r); err != nil {
				auth.WriteJSONError(w, http.StatusForbidden, "csrf validation failed")
				return
			}
		} else if err := s.authMgr.VerifyOriginAndFetchSite(r); err != nil {
			auth.WriteJSONError(w, http.StatusForbidden, "origin check failed")
			return
		}
		s.authMgr.ClearSessionCookie(w)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}
