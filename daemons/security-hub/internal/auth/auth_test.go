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
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
		RPOrigin:        "http://localhost:10311",
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
	authData := []byte("mock-authenticator-data-37-bytes-min!!")
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
