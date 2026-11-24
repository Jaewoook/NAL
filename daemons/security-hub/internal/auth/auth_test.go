package auth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jaewoook/security-hub/internal/config"
)

func addSessionAndCSRF(req *http.Request, mgr *Manager, cookies []*http.Cookie) {
	for _, c := range cookies {
		req.AddCookie(c)
	}
	if tok := mgr.CSRFTokenForRequest(req); tok != "" {
		req.Header.Set(CSRFHeaderName, tok)
	}
}

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
	if len(cookies) < 2 {
		t.Fatalf("expected session + csrf cookies, got %d", len(cookies))
	}

	req := httptest.NewRequest(http.MethodGet, "/api/dashboard", nil)
	addSessionAndCSRF(req, mgr, cookies)
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

	// 3. Single-use CLI break-glass token + invalid token leaves file clean
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

	// 4. WebAuthn Passkey ES256 Registration (with attestationObject + clientDataJSON) + Offline Login
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credIDRaw := []byte("cred-macbook-touchid")
	credIDB64 := base64.RawURLEncoding.EncodeToString(credIDRaw)

	// Begin registration requires POST + auth + CSRF
	regBeginReq := httptest.NewRequest(http.MethodPost, "/api/auth/passkey/register/begin", nil)
	addSessionAndCSRF(regBeginReq, mgr, cookies)
	regBeginW := httptest.NewRecorder()
	mgr.BeginPasskeyRegistration(regBeginW, regBeginReq)
	if regBeginW.Code != http.StatusOK {
		t.Fatalf("BeginPasskeyRegistration returned %d: %s", regBeginW.Code, regBeginW.Body.String())
	}
	var regOpts struct {
		Challenge string `json:"challenge"`
	}
	_ = json.Unmarshal(regBeginW.Body.Bytes(), &regOpts)

	// Finish registration with valid attestationObject + clientDataJSON
	attObj := buildTestAttestationObject(cfg.RPID, credIDRaw, &privKey.PublicKey, 0)
	regClientData, _ := json.Marshal(map[string]string{
		"type":      "webauthn.create",
		"challenge": regOpts.Challenge,
		"origin":    "http://localhost:10311",
	})
	regBody, _ := json.Marshal(map[string]string{
		"credential_id":      credIDB64,
		"label":              "MacBook TouchID",
		"attestation_object": base64.RawURLEncoding.EncodeToString(attObj),
		"client_data_json":   base64.RawURLEncoding.EncodeToString(regClientData),
	})
	regFinReq := httptest.NewRequest(http.MethodPost, "/api/auth/passkey/register/finish", bytes.NewReader(regBody))
	addSessionAndCSRF(regFinReq, mgr, cookies)
	regFinW := httptest.NewRecorder()
	mgr.FinishPasskeyRegistration(regFinW, regFinReq)
	if regFinW.Code != http.StatusOK {
		t.Fatalf("FinishPasskeyRegistration returned %d: %s", regFinW.Code, regFinW.Body.String())
	}

	// Duplicate credential_id rejected
	regBeginReq2 := httptest.NewRequest(http.MethodPost, "/api/auth/passkey/register/begin", nil)
	addSessionAndCSRF(regBeginReq2, mgr, cookies)
	regBeginW2 := httptest.NewRecorder()
	mgr.BeginPasskeyRegistration(regBeginW2, regBeginReq2)
	var regOpts2 struct {
		Challenge string `json:"challenge"`
	}
	_ = json.Unmarshal(regBeginW2.Body.Bytes(), &regOpts2)
	regClientData2, _ := json.Marshal(map[string]string{
		"type":      "webauthn.create",
		"challenge": regOpts2.Challenge,
		"origin":    "http://localhost:10311",
	})
	regBody2, _ := json.Marshal(map[string]string{
		"credential_id":      credIDB64,
		"label":              "Dup Key",
		"attestation_object": base64.RawURLEncoding.EncodeToString(attObj),
		"client_data_json":   base64.RawURLEncoding.EncodeToString(regClientData2),
	})
	regFinReq2 := httptest.NewRequest(http.MethodPost, "/api/auth/passkey/register/finish", bytes.NewReader(regBody2))
	addSessionAndCSRF(regFinReq2, mgr, cookies)
	regFinW2 := httptest.NewRecorder()
	mgr.FinishPasskeyRegistration(regFinW2, regFinReq2)
	if regFinW2.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict for duplicate credential_id, got %d: %s", regFinW2.Code, regFinW2.Body.String())
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
	authData := append(rpIDHash[:], 0x01, 0, 0, 0, 5) // signCount = 5 (> 0)
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
		"credential_id":      credIDB64,
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

	// Verify signCount replay (signCount=4 <= stored 5) is rejected!
	loginBeginW2 := httptest.NewRecorder()
	mgr2.BeginPasskeyLogin(loginBeginW2, httptest.NewRequest(http.MethodPost, "/api/auth/passkey/login/begin", nil))
	var loginOpts2 struct {
		Challenge string `json:"challenge"`
	}
	_ = json.Unmarshal(loginBeginW2.Body.Bytes(), &loginOpts2)
	replayAuthData := append(rpIDHash[:], 0x01, 0, 0, 0, 4)
	replayCD, _ := json.Marshal(map[string]string{
		"type":      "webauthn.get",
		"challenge": loginOpts2.Challenge,
		"origin":    "http://localhost:10311",
	})
	replayHash := sha256.Sum256(replayCD)
	replayDigest := sha256.Sum256(append(append([]byte{}, replayAuthData...), replayHash[:]...))
	replaySig, _ := ecdsa.SignASN1(rand.Reader, privKey, replayDigest[:])
	replayBody, _ := json.Marshal(map[string]string{
		"credential_id":      credIDB64,
		"authenticator_data": base64.RawURLEncoding.EncodeToString(replayAuthData),
		"client_data_json":   base64.RawURLEncoding.EncodeToString(replayCD),
		"signature":          base64.RawURLEncoding.EncodeToString(replaySig),
	})
	replayW := httptest.NewRecorder()
	mgr2.FinishPasskeyLogin(replayW, httptest.NewRequest(http.MethodPost, "/api/auth/passkey/login/finish", bytes.NewReader(replayBody)))
	if replayW.Code != http.StatusUnauthorized || !strings.Contains(replayW.Body.String(), "sign counter") {
		t.Fatalf("expected 401 sign counter regression rejection, got %d: %s", replayW.Code, replayW.Body.String())
	}
}

func TestManager_CookieSecurity_PublicURLCheck(t *testing.T) {
	mgrHTTPS, _ := NewManager(config.AuthConfig{
		PublicURL: "https://securityhub.example.com",
	}, "")
	if !mgrHTTPS.isSecureCookie() {
		t.Fatal("expected isSecureCookie to be true when PublicURL starts with https://")
	}

	// HTTPS OIDCIssuer alone must NOT force Secure=true for plain LAN HTTP PublicURL
	mgrHTTPWithHTTPSIdP, _ := NewManager(config.AuthConfig{
		PublicURL:  "http://192.168.1.10:10311",
		OIDCIssuer: "https://auth.example.com",
	}, "")
	if mgrHTTPWithHTTPSIdP.isSecureCookie() {
		t.Fatal("expected isSecureCookie to remain false for http:// PublicURL even when OIDCIssuer is https://")
	}
}
