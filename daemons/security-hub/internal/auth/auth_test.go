package auth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jaewoook/security-hub/internal/config"
)

func TestManager_StatelessCookieBreakGlassAndWebAuthnPasskey(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "auth_state.json")
	cfg := config.AuthConfig{
		OIDCIssuer:      "https://auth.jaewook.dev/application/o/security-hub/",
		OIDCClientID:    "security-hub",
		SessionSecret:   "super-secret-signing-key-32-bytes",
		SessionTTLHours: 24,
		RPID:            "localhost",
	}

	mgr, err := NewManager(cfg, stateFile)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Stateless Session Cookie works offline (even when Authentik is unreachable)
	w := httptest.NewRecorder()
	if err := mgr.IssueSessionCookie(w, "jaewook@jaewook.dev", "sso"); err != nil {
		t.Fatal(err)
	}
	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected session cookie")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/dashboard", nil)
	req.AddCookie(cookies[0])
	claims, err := mgr.VerifyRequest(req)
	if err != nil || claims.Subject != "jaewook@jaewook.dev" || claims.Method != "sso" {
		t.Fatalf("VerifyRequest failed: %v, claims=%+v", err, claims)
	}

	// 2. Tampered cookie fails
	badReq := httptest.NewRequest(http.MethodGet, "/api/dashboard", nil)
	badReq.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookies[0].Value + "tamper"})
	if _, err := mgr.VerifyRequest(badReq); err == nil {
		t.Fatal("expected tampered cookie to fail verification")
	}

	// 3. Single-use CLI break-glass token
	tok, err := mgr.GenerateBreakGlassToken(5 * time.Minute)
	if err != nil || tok == "" {
		t.Fatalf("GenerateBreakGlassToken failed: %v", err)
	}
	ok1, err := mgr.ConsumeBreakGlassToken(tok)
	if err != nil || !ok1 {
		t.Fatalf("expected first consume of break-glass token to succeed: ok=%v err=%v", ok1, err)
	}
	ok2, _ := mgr.ConsumeBreakGlassToken(tok)
	if ok2 {
		t.Fatal("expected replay of break-glass token to be rejected")
	}

	// 4. WebAuthn Passkey ES256 Registration + Offline Login across reload
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	// Begin registration
	regBeginW := httptest.NewRecorder()
	mgr.BeginPasskeyRegistration(regBeginW, req)
	if regBeginW.Code != http.StatusOK {
		t.Fatalf("BeginPasskeyRegistration returned %d: %s", regBeginW.Code, regBeginW.Body.String())
	}
	var regOpts struct {
		Challenge string `json:"challenge"`
	}
	_ = json.Unmarshal(regBeginW.Body.Bytes(), &regOpts)

	// Finish registration
	regBody, _ := json.Marshal(map[string]string{
		"credential_id":  "cred-macbook-touchid",
		"label":          "MacBook TouchID",
		"public_key_spki": base64.RawURLEncoding.EncodeToString(pubDER),
		"challenge":      regOpts.Challenge,
	})
	regFinReq := httptest.NewRequest(http.MethodPost, "/api/auth/passkey/register/finish", bytes.NewReader(regBody))
	regFinReq.AddCookie(cookies[0])
	regFinW := httptest.NewRecorder()
	mgr.FinishPasskeyRegistration(regFinW, regFinReq)
	if regFinW.Code != http.StatusOK {
		t.Fatalf("FinishPasskeyRegistration returned %d: %s", regFinW.Code, regFinW.Body.String())
	}

	// Reload manager from disk to verify persistence in auth_state.json
	mgr2, err := NewManager(cfg, stateFile)
	if err != nil {
		t.Fatal(err)
	}

	loginBeginW := httptest.NewRecorder()
	mgr2.BeginPasskeyLogin(loginBeginW, httptest.NewRequest(http.MethodPost, "/api/auth/passkey/login/begin", nil))
	if loginBeginW.Code != http.StatusOK {
		t.Fatalf("BeginPasskeyLogin returned %d", loginBeginW.Code)
	}
	var loginOpts struct {
		Challenge string `json:"challenge"`
	}
	_ = json.Unmarshal(loginBeginW.Body.Bytes(), &loginOpts)

	// Simulate WebAuthn assertion signature: sign(authenticatorData || sha256(clientDataJSON))
	rpIDHash := sha256.Sum256([]byte(cfg.RPID))
	authData := append(rpIDHash[:], 0x01, 0, 0, 0, 1) // 32-byte RP ID hash + 0x01 UP flag + 4-byte counter = 37 bytes
	clientDataJSON, _ := json.Marshal(map[string]string{
		"type":      "webauthn.get",
		"challenge": loginOpts.Challenge,
		"origin":    "http://localhost:10311",
	})
	clientHash := sha256.Sum256(clientDataJSON)
	signedPayload := append(append([]byte{}, authData...), clientHash[:]...)
	digest := sha256.Sum256(signedPayload)
	sigASN1, err := ecdsa.SignASN1(rand.Reader, privKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	loginFinBody, _ := json.Marshal(map[string]string{
		"credential_id":      "cred-macbook-touchid",
		"authenticator_data": base64.RawURLEncoding.EncodeToString(authData),
		"client_data_json":   base64.RawURLEncoding.EncodeToString(clientDataJSON),
		"signature":          base64.RawURLEncoding.EncodeToString(sigASN1),
	})
	loginFinW := httptest.NewRecorder()
	mgr2.FinishPasskeyLogin(loginFinW, httptest.NewRequest(http.MethodPost, "/api/auth/passkey/login/finish", bytes.NewReader(loginFinBody)))
	if loginFinW.Code != http.StatusOK {
		t.Fatalf("FinishPasskeyLogin returned %d: %s", loginFinW.Code, loginFinW.Body.String())
	}
	if len(loginFinW.Result().Cookies()) == 0 {
		t.Fatal("expected session cookie issued after Passkey login")
	}
}

func TestExtractUsernameFromJWT(t *testing.T) {
	// Case 1: preferred_username takes precedence
	claims1 := `{"sub":"user-123","email":"dev.jaewook@gmail.com","preferred_username":"jaewook"}`
	jwt1 := "header." + base64.RawURLEncoding.EncodeToString([]byte(claims1)) + ".sig"
	if u := extractUsernameFromJWT(jwt1); u != "jaewook" {
		t.Fatalf("expected jaewook, got %q", u)
	}

	// Case 2: email fallback strips domain to username
	claims2 := `{"sub":"user-456","email":"admin.ops@company.org"}`
	jwt2 := "header." + base64.RawURLEncoding.EncodeToString([]byte(claims2)) + ".sig"
	if u := extractUsernameFromJWT(jwt2); u != "admin.ops" {
		t.Fatalf("expected admin.ops, got %q", u)
	}

	// Case 3: subject fallback
	claims3 := `{"sub":"service-account"}`
	jwt3 := "header." + base64.RawURLEncoding.EncodeToString([]byte(claims3)) + ".sig"
	if u := extractUsernameFromJWT(jwt3); u != "service-account" {
		t.Fatalf("expected service-account, got %q", u)
	}
}

func TestOIDC_StateCSRF_And_IDTokenVerification(t *testing.T) {
	mgr, _ := NewManager(config.AuthConfig{
		OIDCIssuer:   "https://auth.example.com",
		OIDCClientID: "my-client",
		RedirectURL:  "https://hub.example.com/api/auth/oidc/callback",
	}, "")

	// 1. Start OIDC Login sets state cookie and redirect param
	loginW := httptest.NewRecorder()
	loginR := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/login", nil)
	mgr.StartOIDCLogin(loginW, loginR)
	if loginW.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d", loginW.Code)
	}
	cookies := loginW.Result().Cookies()
	var stateCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == OIDCStateCookieName {
			stateCookie = c
			break
		}
	}
	if stateCookie == nil || stateCookie.Value == "" {
		t.Fatal("expected OIDC state cookie to be set")
	}

	loc, _ := url.Parse(loginW.Header().Get("Location"))
	stateParam := loc.Query().Get("state")
	if stateParam != stateCookie.Value {
		t.Fatalf("expected state param %q to match state cookie %q", stateParam, stateCookie.Value)
	}

	// 2. Callback without state cookie fails (CSRF protection)
	cbW := httptest.NewRecorder()
	cbR := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/callback?code=1234&state="+stateParam, nil)
	mgr.HandleOIDCCallback(cbW, cbR)
	if cbW.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request on missing state cookie, got %d", cbW.Code)
	}

	// 3. Callback with mismatched state fails
	cbW2 := httptest.NewRecorder()
	cbR2 := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/callback?code=1234&state=wrong-state", nil)
	cbR2.AddCookie(stateCookie)
	mgr.HandleOIDCCallback(cbW2, cbR2)
	if cbW2.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request on state mismatch, got %d", cbW2.Code)
	}

	// 4. Token validation: expired token rejected
	now := time.Now().UTC().Unix()
	expiredClaims := fmt.Sprintf(`{"sub":"admin","aud":"my-client","iss":"https://auth.example.com","exp":%d}`, now-120)
	expiredJWT := "h." + base64.RawURLEncoding.EncodeToString([]byte(expiredClaims)) + ".s"
	if _, err := mgr.verifyAndExtractIDToken(expiredJWT); err == nil {
		t.Fatal("expected expired ID token to be rejected")
	}

	// 5. Token validation: audience mismatch rejected
	audMismatch := fmt.Sprintf(`{"sub":"admin","aud":"other-client","iss":"https://auth.example.com","exp":%d}`, now+600)
	audJWT := "h." + base64.RawURLEncoding.EncodeToString([]byte(audMismatch)) + ".s"
	if _, err := mgr.verifyAndExtractIDToken(audJWT); err == nil {
		t.Fatal("expected audience mismatch to be rejected")
	}

	// 6. Token validation: missing exp rejected
	missingExpClaims := `{"sub":"admin","aud":"my-client","iss":"https://auth.example.com"}`
	missingExpJWT := "h." + base64.RawURLEncoding.EncodeToString([]byte(missingExpClaims)) + ".s"
	if _, err := mgr.verifyAndExtractIDToken(missingExpJWT); err == nil {
		t.Fatal("expected ID token missing exp to be rejected")
	}

	// 7. Token validation: missing aud rejected
	missingAudClaims := fmt.Sprintf(`{"sub":"admin","iss":"https://auth.example.com","exp":%d}`, now+600)
	missingAudJWT := "h." + base64.RawURLEncoding.EncodeToString([]byte(missingAudClaims)) + ".s"
	if _, err := mgr.verifyAndExtractIDToken(missingAudJWT); err == nil {
		t.Fatal("expected ID token missing aud to be rejected")
	}

	// 8. Token validation: attacker issuer subdomain rejected
	spoofedIssClaims := fmt.Sprintf(`{"sub":"admin","aud":"my-client","iss":"https://auth.example.com.attacker.com","exp":%d}`, now+600)
	spoofedIssJWT := "h." + base64.RawURLEncoding.EncodeToString([]byte(spoofedIssClaims)) + ".s"
	if _, err := mgr.verifyAndExtractIDToken(spoofedIssJWT); err == nil {
		t.Fatal("expected issuer subdomain spoofing to be rejected")
	}

	// 9. Token validation: missing iss rejected
	missingIssClaims := fmt.Sprintf(`{"sub":"admin","aud":"my-client","exp":%d}`, now+600)
	missingIssJWT := "h." + base64.RawURLEncoding.EncodeToString([]byte(missingIssClaims)) + ".s"
	if _, err := mgr.verifyAndExtractIDToken(missingIssJWT); err == nil {
		t.Fatal("expected ID token missing iss to be rejected")
	}

	// 10. Token validation: valid token accepted
	validClaims := fmt.Sprintf(`{"sub":"admin-sub","preferred_username":"jaewook","aud":"my-client","iss":"https://auth.example.com","exp":%d}`, now+600)
	validJWT := "h." + base64.RawURLEncoding.EncodeToString([]byte(validClaims)) + ".s"
	sub, err := mgr.verifyAndExtractIDToken(validJWT)
	if err != nil {
		t.Fatalf("expected valid token to pass, got: %v", err)
	}
	if sub != "jaewook" {
		t.Fatalf("expected username jaewook, got %q", sub)
	}
}

func TestManager_CookieSecurity_PublicURLCheck(t *testing.T) {
	// Only PublicURL set to HTTPS
	mgrHTTPS, _ := NewManager(config.AuthConfig{
		PublicURL: "https://securityhub.example.com",
	}, "")
	if !mgrHTTPS.isSecureCookie() {
		t.Fatal("expected isSecureCookie to be true when PublicURL starts with https://")
	}

	// PublicURL set to HTTP
	mgrHTTP, _ := NewManager(config.AuthConfig{
		PublicURL: "http://localhost:10311",
	}, "")
	if mgrHTTP.isSecureCookie() {
		t.Fatal("expected isSecureCookie to be false when PublicURL starts with http://")
	}
}

func TestPasskey_SecurityChecks_RPIDHash_UPFlag(t *testing.T) {
	mgr, _ := NewManager(config.AuthConfig{
		RPID: "securityhub.jaewook.dev",
	}, "")
	ch, _ := mgr.newChallenge()

	// 1. Missing UP flag rejected
	rpIDHash := sha256.Sum256([]byte("securityhub.jaewook.dev"))
	badAuthData := append(rpIDHash[:], 0x00, 0, 0, 0, 1) // UP flag bit 0 is 0!

	clientDataJSON, _ := json.Marshal(map[string]string{
		"type":      "webauthn.get",
		"challenge": ch,
		"origin":    "https://securityhub.jaewook.dev",
	})

	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{
		"credential_id":      "cred-1",
		"authenticator_data": base64.RawURLEncoding.EncodeToString(badAuthData),
		"client_data_json":   base64.RawURLEncoding.EncodeToString(clientDataJSON),
		"signature":          "dummy-sig",
	})
	mgr.state.Passkeys = append(mgr.state.Passkeys, PasskeyCredential{
		CredentialID: "cred-1",
		Label:        "Key",
	})
	mgr.FinishPasskeyLogin(w, httptest.NewRequest(http.MethodPost, "/api/auth/passkey/login/finish", bytes.NewReader(body)))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request on missing UP flag, got %d", w.Code)
	}

	// 2. RP ID Hash mismatch rejected
	ch2, _ := mgr.newChallenge()
	wrongRPIDHash := sha256.Sum256([]byte("evil.com"))
	wrongRPIDAuthData := append(wrongRPIDHash[:], 0x01, 0, 0, 0, 1)

	clientDataJSON2, _ := json.Marshal(map[string]string{
		"type":      "webauthn.get",
		"challenge": ch2,
		"origin":    "https://securityhub.jaewook.dev",
	})
	w2 := httptest.NewRecorder()
	body2, _ := json.Marshal(map[string]string{
		"credential_id":      "cred-1",
		"authenticator_data": base64.RawURLEncoding.EncodeToString(wrongRPIDAuthData),
		"client_data_json":   base64.RawURLEncoding.EncodeToString(clientDataJSON2),
		"signature":          "dummy-sig",
	})
	mgr.FinishPasskeyLogin(w2, httptest.NewRequest(http.MethodPost, "/api/auth/passkey/login/finish", bytes.NewReader(body2)))
	if w2.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request on RP ID mismatch, got %d", w2.Code)
	}

	// 3. Subdomain origin spoofing rejected (securityhub.jaewook.dev.attacker.com contains RPID but host differs)
	ch3, _ := mgr.newChallenge()
	validAuthData := append(rpIDHash[:], 0x01, 0, 0, 0, 1)
	clientDataJSON3, _ := json.Marshal(map[string]string{
		"type":      "webauthn.get",
		"challenge": ch3,
		"origin":    "https://securityhub.jaewook.dev.attacker.com",
	})
	w3 := httptest.NewRecorder()
	body3, _ := json.Marshal(map[string]string{
		"credential_id":      "cred-1",
		"authenticator_data": base64.RawURLEncoding.EncodeToString(validAuthData),
		"client_data_json":   base64.RawURLEncoding.EncodeToString(clientDataJSON3),
		"signature":          base64.RawURLEncoding.EncodeToString([]byte("dummy-sig")),
	})
	mgr.FinishPasskeyLogin(w3, httptest.NewRequest(http.MethodPost, "/api/auth/passkey/login/finish", bytes.NewReader(body3)))
	if w3.Code != http.StatusBadRequest || !strings.Contains(w3.Body.String(), "origin mismatch") {
		t.Fatalf("expected 400 Bad Request with 'origin mismatch' on subdomain origin spoofing, got %d: %s", w3.Code, w3.Body.String())
	}

	// 4. Empty origin rejected
	ch4, _ := mgr.newChallenge()
	clientDataJSON4, _ := json.Marshal(map[string]string{
		"type":      "webauthn.get",
		"challenge": ch4,
		"origin":    "",
	})
	w4 := httptest.NewRecorder()
	body4, _ := json.Marshal(map[string]string{
		"credential_id":      "cred-1",
		"authenticator_data": base64.RawURLEncoding.EncodeToString(validAuthData),
		"client_data_json":   base64.RawURLEncoding.EncodeToString(clientDataJSON4),
		"signature":          base64.RawURLEncoding.EncodeToString([]byte("dummy-sig")),
	})
	mgr.FinishPasskeyLogin(w4, httptest.NewRequest(http.MethodPost, "/api/auth/passkey/login/finish", bytes.NewReader(body4)))
	if w4.Code != http.StatusBadRequest || !strings.Contains(w4.Body.String(), "origin") {
		t.Fatalf("expected 400 Bad Request on empty origin, got %d: %s", w4.Code, w4.Body.String())
	}
}
