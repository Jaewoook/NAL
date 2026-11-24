package auth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jaewoook/security-hub/internal/config"
)

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

func cfgEmptyRP() config.AuthConfig {
	return config.AuthConfig{SessionSecret: "test-secret-0123456789abcdef0123456789"}
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
	priv.X.FillBytes(xBytes)
	priv.Y.FillBytes(yBytes)
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
