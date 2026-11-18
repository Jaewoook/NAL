package auth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
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

func buildCBORBytesHeader(major byte, n uint64) []byte {
	m := major << 5
	switch {
	case n < 24:
		return []byte{m | byte(n)}
	case n < 256:
		return []byte{m | 24, byte(n)}
	default:
		b := make([]byte, 3)
		b[0] = m | 25
		binary.BigEndian.PutUint16(b[1:3], uint16(n))
		return b
	}
}

func buildCBORByteString(b []byte) []byte {
	out := buildCBORBytesHeader(2, uint64(len(b)))
	return append(out, b...)
}

func buildCBORTextString(s string) []byte {
	out := buildCBORBytesHeader(3, uint64(len(s)))
	return append(out, []byte(s)...)
}

func buildCBORInt(v int64) []byte {
	if v >= 0 {
		return buildCBORBytesHeader(0, uint64(v))
	}
	return buildCBORBytesHeader(1, uint64(-1-v))
}

func buildTestAttestationObject(rpid string, credID []byte, pub *ecdsa.PublicKey, signCount uint32) []byte {
	xBytes := make([]byte, 32)
	yBytes := make([]byte, 32)
	pub.X.FillBytes(xBytes)
	pub.Y.FillBytes(yBytes)

	// COSE EC2 P-256 key map with 5 entries: 1:2, 3:-7, -1:1, -2:x, -3:y
	var cose bytes.Buffer
	cose.Write(buildCBORBytesHeader(5, 5))
	cose.Write(buildCBORInt(1))
	cose.Write(buildCBORInt(2))
	cose.Write(buildCBORInt(3))
	cose.Write(buildCBORInt(-7))
	cose.Write(buildCBORInt(-1))
	cose.Write(buildCBORInt(1))
	cose.Write(buildCBORInt(-2))
	cose.Write(buildCBORByteString(xBytes))
	cose.Write(buildCBORInt(-3))
	cose.Write(buildCBORByteString(yBytes))

	rpHash := sha256.Sum256([]byte(rpid))
	var authData bytes.Buffer
	authData.Write(rpHash[:])
	authData.WriteByte(0x41) // UP (0x01) | AT (0x40)
	var sc [4]byte
	binary.BigEndian.PutUint32(sc[:], signCount)
	authData.Write(sc[:])
	authData.Write(make([]byte, 16)) // zero AAGUID
	var cidLen [2]byte
	binary.BigEndian.PutUint16(cidLen[:], uint16(len(credID)))
	authData.Write(cidLen[:])
	authData.Write(credID)
	authData.Write(cose.Bytes())

	var att bytes.Buffer
	att.Write(buildCBORBytesHeader(5, 2))
	att.Write(buildCBORTextString("fmt"))
	att.Write(buildCBORTextString("none"))
	att.Write(buildCBORTextString("authData"))
	att.Write(buildCBORByteString(authData.Bytes()))
	return att.Bytes()
}

func signTestRS256JWT(t *testing.T, priv *rsa.PrivateKey, kid, alg string, claimsJSON string) string {
	t.Helper()
	hdrJSON := fmt.Sprintf(`{"alg":%q,"kid":%q,"typ":"JWT"}`, alg, kid)
	hdrB64 := base64.RawURLEncoding.EncodeToString([]byte(hdrJSON))
	payB64 := base64.RawURLEncoding.EncodeToString([]byte(claimsJSON))
	signingInput := hdrB64 + "." + payB64
	if strings.EqualFold(alg, "none") {
		return signingInput + "."
	}
	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
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

func TestExtractUsernameFromJWT(t *testing.T) {
	claims1 := `{"sub":"user-123","email":"dev.jaewook@gmail.com","preferred_username":"jaewook"}`
	jwt1 := "header." + base64.RawURLEncoding.EncodeToString([]byte(claims1)) + ".sig"
	if u := extractUsernameFromJWT(jwt1); u != "jaewook" {
		t.Fatalf("expected jaewook, got %q", u)
	}

	claims2 := `{"sub":"user-456","email":"admin.ops@company.org"}`
	jwt2 := "header." + base64.RawURLEncoding.EncodeToString([]byte(claims2)) + ".sig"
	if u := extractUsernameFromJWT(jwt2); u != "admin.ops" {
		t.Fatalf("expected admin.ops, got %q", u)
	}

	claims3 := `{"sub":"service-account"}`
	jwt3 := "header." + base64.RawURLEncoding.EncodeToString([]byte(claims3)) + ".sig"
	if u := extractUsernameFromJWT(jwt3); u != "service-account" {
		t.Fatalf("expected service-account, got %q", u)
	}
}

func TestOIDC_StateCSRF_Nonce_JWKS_And_IDTokenVerification(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	var idpSrv *httptest.Server
	var nextIDToken string
	idpSrv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":                 idpSrv.URL,
				"authorization_endpoint": idpSrv.URL + "/authorize",
				"token_endpoint":         idpSrv.URL + "/token",
				"jwks_uri":               idpSrv.URL + "/jwks",
			})
		case "/jwks":
			eBytes := []byte{0x01, 0x00, 0x01} // 65537
			_ = json.NewEncoder(w).Encode(map[string]any{
				"keys": []map[string]string{
					{
						"kty": "RSA",
						"use": "sig",
						"alg": "RS256",
						"kid": "key-1",
						"n":   base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes()),
						"e":   base64.RawURLEncoding.EncodeToString(eBytes),
					},
				},
			})
		case "/token":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"id_token": nextIDToken,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer idpSrv.Close()

	mgr, err := NewManager(config.AuthConfig{
		OIDCIssuer:   idpSrv.URL,
		OIDCClientID: "my-client",
		RedirectURL:  "https://hub.example.com/api/auth/oidc/callback",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	mgr.SetHTTPClient(idpSrv.Client())

	// 1. Start OIDC Login sets state + nonce cookies and query params
	loginW := httptest.NewRecorder()
	loginR := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/login", nil)
	mgr.StartOIDCLogin(loginW, loginR)
	if loginW.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d: %s", loginW.Code, loginW.Body.String())
	}
	var stateCookie, nonceCookie *http.Cookie
	for _, c := range loginW.Result().Cookies() {
		if c.Name == OIDCStateCookieName {
			stateCookie = c
		} else if c.Name == OIDCNonceCookieName {
			nonceCookie = c
		}
	}
	if stateCookie == nil || stateCookie.Value == "" || nonceCookie == nil || nonceCookie.Value == "" {
		t.Fatal("expected OIDC state and nonce cookies to be set")
	}

	loc, _ := url.Parse(loginW.Header().Get("Location"))
	stateParam := loc.Query().Get("state")
	nonceParam := loc.Query().Get("nonce")
	if stateParam != stateCookie.Value || nonceParam != nonceCookie.Value {
		t.Fatalf("expected state/nonce params to match cookies")
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
	cbR2.AddCookie(nonceCookie)
	mgr.HandleOIDCCallback(cbW2, cbR2)
	if cbW2.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request on state mismatch, got %d", cbW2.Code)
	}

	ctx := context.Background()
	now := time.Now().UTC().Unix()

	// 4. Reject alg=none & wrong signing key
	noneClaims := fmt.Sprintf(`{"sub":"admin","aud":"my-client","iss":%q,"nonce":%q,"exp":%d}`, idpSrv.URL, nonceParam, now+600)
	noneJWT := signTestRS256JWT(t, rsaKey, "key-1", "none", noneClaims)
	if _, err := mgr.verifyAndExtractIDToken(ctx, noneJWT, nonceParam); err == nil {
		t.Fatal("expected alg=none JWT to be rejected")
	}
	wrongSigJWT := signTestRS256JWT(t, wrongKey, "key-1", "RS256", noneClaims)
	if _, err := mgr.verifyAndExtractIDToken(ctx, wrongSigJWT, nonceParam); err == nil {
		t.Fatal("expected JWT signed by wrong RSA key to be rejected")
	}

	// 5. Reject expired, wrong aud, missing exp, missing aud, multi-aud without azp, nonce mismatch, http issuer
	expiredJWT := signTestRS256JWT(t, rsaKey, "key-1", "RS256", fmt.Sprintf(`{"sub":"admin","aud":"my-client","iss":%q,"nonce":%q,"exp":%d}`, idpSrv.URL, nonceParam, now-120))
	if _, err := mgr.verifyAndExtractIDToken(ctx, expiredJWT, nonceParam); err == nil {
		t.Fatal("expected expired ID token rejected")
	}
	audMismatchJWT := signTestRS256JWT(t, rsaKey, "key-1", "RS256", fmt.Sprintf(`{"sub":"admin","aud":"other","iss":%q,"nonce":%q,"exp":%d}`, idpSrv.URL, nonceParam, now+600))
	if _, err := mgr.verifyAndExtractIDToken(ctx, audMismatchJWT, nonceParam); err == nil {
		t.Fatal("expected audience mismatch rejected")
	}
	multiAudNoAzp := signTestRS256JWT(t, rsaKey, "key-1", "RS256", fmt.Sprintf(`{"sub":"admin","aud":["my-client","other"],"iss":%q,"nonce":%q,"exp":%d}`, idpSrv.URL, nonceParam, now+600))
	if _, err := mgr.verifyAndExtractIDToken(ctx, multiAudNoAzp, nonceParam); err == nil {
		t.Fatal("expected multi-audience ID token without azp to be rejected")
	}
	wrongNonce := signTestRS256JWT(t, rsaKey, "key-1", "RS256", fmt.Sprintf(`{"sub":"admin","aud":"my-client","iss":%q,"nonce":"wrong","exp":%d}`, idpSrv.URL, now+600))
	if _, err := mgr.verifyAndExtractIDToken(ctx, wrongNonce, nonceParam); err == nil {
		t.Fatal("expected nonce mismatch to be rejected")
	}

	// 6. Full HandleOIDCCallback with valid RS256 signed JWT
	nextIDToken = signTestRS256JWT(t, rsaKey, "key-1", "RS256", fmt.Sprintf(`{"sub":"admin-sub","preferred_username":"jaewook","aud":["my-client","other"],"azp":"my-client","iss":%q,"nonce":%q,"exp":%d}`, idpSrv.URL, nonceParam, now+600))
	cbOK := httptest.NewRecorder()
	cbOKReq := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/callback?code=authcode&state="+stateParam, nil)
	cbOKReq.AddCookie(stateCookie)
	cbOKReq.AddCookie(nonceCookie)
	mgr.HandleOIDCCallback(cbOK, cbOKReq)
	if cbOK.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect on valid OIDC callback, got %d: %s", cbOK.Code, cbOK.Body.String())
	}
	if len(cbOK.Result().Cookies()) < 2 {
		t.Fatal("expected session cookie issued after OIDC callback")
	}

	// 7. Insecure http:// OIDCIssuer rejected
	httpMgr, _ := NewManager(config.AuthConfig{
		OIDCIssuer:   "http://auth.example.com",
		OIDCClientID: "my-client",
	}, "")
	httpW := httptest.NewRecorder()
	httpMgr.StartOIDCLogin(httpW, httptest.NewRequest(http.MethodGet, "/api/auth/oidc/login", nil))
	if httpW.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 on http:// OIDCIssuer, got %d", httpW.Code)
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

func TestPasskey_SecurityChecks_RPIDHash_UPFlag(t *testing.T) {
	mgr, _ := NewManager(config.AuthConfig{
		RPID: "securityhub.jaewook.dev",
	}, "")
	ch, err := mgr.newChallengeFor("login", "")
	if err != nil {
		t.Fatal(err)
	}

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
	ch2, _ := mgr.newChallengeFor("login", "")
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

	// 3. Subdomain origin spoofing rejected (securityhub.jaewook.dev.attacker.com)
	ch3, _ := mgr.newChallengeFor("login", "")
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
		t.Fatalf("expected 400 Bad Request with 'origin mismatch' on subdomain spoofing, got %d: %s", w3.Code, w3.Body.String())
	}

	// 4. Plain http:// origin rejected for non-localhost RPID
	ch4, _ := mgr.newChallengeFor("login", "")
	clientDataJSON4, _ := json.Marshal(map[string]string{
		"type":      "webauthn.get",
		"challenge": ch4,
		"origin":    "http://securityhub.jaewook.dev",
	})
	w4 := httptest.NewRecorder()
	body4, _ := json.Marshal(map[string]string{
		"credential_id":      "cred-1",
		"authenticator_data": base64.RawURLEncoding.EncodeToString(validAuthData),
		"client_data_json":   base64.RawURLEncoding.EncodeToString(clientDataJSON4),
		"signature":          base64.RawURLEncoding.EncodeToString([]byte("dummy-sig")),
	})
	mgr.FinishPasskeyLogin(w4, httptest.NewRequest(http.MethodPost, "/api/auth/passkey/login/finish", bytes.NewReader(body4)))
	if w4.Code != http.StatusBadRequest || !strings.Contains(w4.Body.String(), "origin mismatch") {
		t.Fatalf("expected 400 Bad Request on http:// non-localhost origin, got %d: %s", w4.Code, w4.Body.String())
	}

	// 5. Empty RPID fails cleanly instead of bypassing checks
	emptyMgr, _ := NewManager(config.AuthConfig{}, "")
	emptyW := httptest.NewRecorder()
	emptyMgr.BeginPasskeyLogin(emptyW, httptest.NewRequest(http.MethodPost, "/api/auth/passkey/login/begin", nil))
	if emptyW.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request when RPID is empty, got %d", emptyW.Code)
	}

	// 6. Corrupt auth_state.json returns error rather than silently overwriting
	corruptPath := filepath.Join(t.TempDir(), "corrupt_auth.json")
	_ = os.WriteFile(corruptPath, []byte("{corrupt-json"), 0600)
	if _, err := NewManager(cfgEmptyRP(), corruptPath); err == nil {
		t.Fatal("expected error when loading corrupt auth_state.json")
	}
}

func cfgEmptyRP() config.AuthConfig {
	return config.AuthConfig{SessionSecret: "test-secret-0123456789abcdef0123456789"}
}

func TestAuth_Round2CBORMapKeyAndColdOIDCDiscovery(t *testing.T) {
	// 1. Non-primitive CBOR map keys ([]byte, array, map) return error without panicking
	maliciousPayloads := [][]byte{
		{0xa1, 0x41, 0x01, 0x01}, // {h'01': 1}
		{0xa1, 0x80, 0x01},       // {[]: 1}
		{0xa1, 0xa0, 0x01},       // {{}: 1}
	}
	for _, raw := range maliciousPayloads {
		if _, err := parseAndVerifyAttestationObject(raw, "localhost"); err == nil || !strings.Contains(err.Error(), "unsupported CBOR map key type") {
			t.Fatalf("expected unsupported CBOR map key type error for %x, got: %v", raw, err)
		}
	}

	// 2. StartOIDCLogin discovers authorization_endpoint on cold cache AND refreshes after 10m TTL expiry
	authEndpointPath := "/custom-sso/auth"
	var idpSrv *httptest.Server
	idpSrv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":                 idpSrv.URL,
				"authorization_endpoint": idpSrv.URL + authEndpointPath,
				"token_endpoint":         idpSrv.URL + "/custom-sso/token",
				"jwks_uri":               idpSrv.URL + "/custom-sso/jwks",
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer idpSrv.Close()

	mgr, err := NewManager(config.AuthConfig{
		OIDCIssuer:    idpSrv.URL,
		OIDCClientID:  "hub-client",
		RedirectURL:   "https://hub.example.org/api/auth/oidc/callback",
		SessionSecret: "test-secret-0123456789abcdef0123456789",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	mgr.httpClient = idpSrv.Client()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/login", nil)
	mgr.StartOIDCLogin(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect on StartOIDCLogin, got %d (%s)", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, idpSrv.URL+"/custom-sso/auth?") {
		t.Fatalf("expected cold StartOIDCLogin to redirect to discovered authorization_endpoint %s/custom-sso/auth, got %q", idpSrv.URL, loc)
	}

	// Expire discovery TTL and change advertised authorization_endpoint
	authEndpointPath = "/custom-sso/auth-v2"
	mgr.oidcMu.Lock()
	mgr.oidcDocFetched = time.Now().Add(-15 * time.Minute)
	mgr.oidcMu.Unlock()

	rec2 := httptest.NewRecorder()
	mgr.StartOIDCLogin(rec2, httptest.NewRequest(http.MethodGet, "/api/auth/oidc/login", nil))
	if rec2.Code != http.StatusFound || !strings.HasPrefix(rec2.Header().Get("Location"), idpSrv.URL+"/custom-sso/auth-v2?") {
		t.Fatalf("expected expired OIDC discovery cache to refresh authorization_endpoint, got %d location=%q", rec2.Code, rec2.Header().Get("Location"))
	}

	// 3. WebAuthn attestationObject with ED (0x80) extensions map is accepted; trailing non-ED bytes (even 0x20 whitespace) are rejected
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	xBytes := make([]byte, 32)
	yBytes := make([]byte, 32)
	priv.PublicKey.X.FillBytes(xBytes)
	priv.PublicKey.Y.FillBytes(yBytes)
	var cose bytes.Buffer
	cose.Write(buildCBORBytesHeader(5, 5))
	cose.Write(buildCBORInt(1))
	cose.Write(buildCBORInt(2))
	cose.Write(buildCBORInt(3))
	cose.Write(buildCBORInt(-7))
	cose.Write(buildCBORInt(-1))
	cose.Write(buildCBORInt(1))
	cose.Write(buildCBORInt(-2))
	cose.Write(buildCBORByteString(xBytes))
	cose.Write(buildCBORInt(-3))
	cose.Write(buildCBORByteString(yBytes))

	rpHash := sha256.Sum256([]byte("localhost"))
	makeAttWithTail := func(flags byte, tail []byte) []byte {
		var authData bytes.Buffer
		authData.Write(rpHash[:])
		authData.WriteByte(flags)
		authData.Write([]byte{0, 0, 0, 1})
		authData.Write(make([]byte, 16))
		authData.Write([]byte{0, 4})
		authData.Write([]byte("cred"))
		authData.Write(cose.Bytes())
		authData.Write(tail)
		var att bytes.Buffer
		att.Write(buildCBORBytesHeader(5, 2))
		att.Write(buildCBORTextString("fmt"))
		att.Write(buildCBORTextString("none"))
		att.Write(buildCBORTextString("authData"))
		att.Write(buildCBORByteString(authData.Bytes()))
		return att.Bytes()
	}

	var extMap bytes.Buffer
	extMap.Write(buildCBORBytesHeader(5, 1))
	extMap.Write(buildCBORTextString("credProtect"))
	extMap.Write(buildCBORInt(1))

	if parsed, err := parseAndVerifyAttestationObject(makeAttWithTail(0xc1, extMap.Bytes()), "localhost"); err != nil || len(parsed.PublicKeySPKI) == 0 {
		t.Fatalf("expected valid ED extensions attestationObject to parse, got err=%v parsed=%+v", err, parsed)
	}
	if _, err := parseAndVerifyAttestationObject(makeAttWithTail(0x41, []byte{' '}), "localhost"); err == nil || !strings.Contains(err.Error(), "unexpected trailing bytes") {
		t.Fatalf("expected trailing space byte without ED flag to be rejected, got err=%v", err)
	}
}
