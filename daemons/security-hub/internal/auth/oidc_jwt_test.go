package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jaewoook/security-hub/internal/config"
)

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
		switch c.Name {
		case OIDCStateCookieName:
			stateCookie = c
		case OIDCNonceCookieName:
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
