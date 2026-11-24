package auth

import (
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (m *Manager) effectiveRPID() string {
	if rpid := strings.TrimSpace(m.cfg.RPID); rpid != "" {
		return rpid
	}
	for _, candidate := range []string{m.cfg.PublicURL, m.cfg.RedirectURL} {
		if candidate == "" {
			continue
		}
		if u, err := url.Parse(candidate); err == nil && u.Hostname() != "" {
			return u.Hostname()
		}
	}
	return ""
}

func (m *Manager) isValidWebAuthnOrigin(originStr, rpid string) bool {
	if originStr == "" || rpid == "" {
		return false
	}
	u, err := url.Parse(originStr)
	if err != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	if !strings.EqualFold(u.Hostname(), rpid) {
		return false
	}
	scheme := strings.ToLower(u.Scheme)
	if m.isSecureCookie() && scheme != "https" {
		return false
	}
	if scheme == "https" {
		return true
	}
	if scheme == "http" {
		hostLower := strings.ToLower(u.Hostname())
		return hostLower == "localhost" || hostLower == "127.0.0.1" || hostLower == "::1"
	}
	return false
}

func (m *Manager) pruneExpiredChallengesLocked() {
	now := time.Now().UTC()
	for ch, entry := range m.challenges {
		if now.After(entry.ExpiresAt) {
			delete(m.challenges, ch)
		}
	}
}

var errTooManyChallenges = errors.New("too many pending WebAuthn challenges")

func (m *Manager) newChallengeFor(kind, subject string) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	ch := base64.RawURLEncoding.EncodeToString(buf)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneExpiredChallengesLocked()
	if len(m.challenges) >= maxPendingChallenges {
		return "", errTooManyChallenges
	}
	m.challenges[ch] = challengeEntry{
		ExpiresAt: time.Now().UTC().Add(5 * time.Minute),
		Kind:      kind,
		Subject:   subject,
	}
	return ch, nil
}

func (m *Manager) consumeChallengeFor(ch, expectedKind, expectedSubject string) bool {
	if ch == "" {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneExpiredChallengesLocked()
	entry, ok := m.challenges[ch]
	if !ok {
		return false
	}
	if entry.Kind != expectedKind {
		return false
	}
	if expectedSubject != "" && entry.Subject != expectedSubject {
		return false
	}
	delete(m.challenges, ch)
	return time.Now().UTC().Before(entry.ExpiresAt)
}

func (m *Manager) requireAuthenticatedRPID(w http.ResponseWriter, r *http.Request) (*SessionClaims, string, bool) {
	if r.Method != http.MethodPost {
		WriteJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return nil, "", false
	}
	claims, err := m.VerifyRequest(r)
	if err != nil {
		WriteJSONError(w, http.StatusUnauthorized, "unauthorized")
		return nil, "", false
	}
	if err := m.VerifyCSRF(r); err != nil {
		WriteJSONError(w, http.StatusForbidden, "csrf validation failed")
		return nil, "", false
	}
	rpid := m.effectiveRPID()
	if rpid == "" {
		WriteJSONError(w, http.StatusBadRequest, "WebAuthn RP ID is not configured")
		return nil, "", false
	}
	return claims, rpid, true
}

func (m *Manager) requireOriginAndRPID(w http.ResponseWriter, r *http.Request) (string, bool) {
	if r.Method != http.MethodPost {
		WriteJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return "", false
	}
	if err := m.VerifyOriginAndFetchSite(r); err != nil {
		WriteJSONError(w, http.StatusForbidden, "origin check failed")
		return "", false
	}
	rpid := m.effectiveRPID()
	if rpid == "" {
		WriteJSONError(w, http.StatusBadRequest, "WebAuthn RP ID is not configured")
		return "", false
	}
	return rpid, true
}

func (m *Manager) verifyWebAuthnClientData(clientDataBytes []byte, expectedType, rpid, kind, subject string, challengeErrStatus int, challengeErrMsg string) (int, string) {
	var clientData struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
		Origin    string `json:"origin"`
	}
	if err := json.Unmarshal(clientDataBytes, &clientData); err != nil {
		return http.StatusBadRequest, "invalid clientDataJSON"
	}
	if clientData.Type != expectedType {
		return http.StatusBadRequest, "invalid clientData type"
	}
	if !m.isValidWebAuthnOrigin(clientData.Origin, rpid) {
		return http.StatusBadRequest, "clientData origin mismatch"
	}
	if !m.consumeChallengeFor(clientData.Challenge, kind, subject) {
		return challengeErrStatus, challengeErrMsg
	}
	return 0, ""
}

func (m *Manager) BeginPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	claims, rpid, ok := m.requireAuthenticatedRPID(w, r)
	if !ok {
		return
	}
	ch, err := m.newChallengeFor("register", claims.Subject)
	if err != nil {
		if errors.Is(err, errTooManyChallenges) {
			WriteJSONError(w, http.StatusTooManyRequests, err.Error())
			return
		}
		WriteJSONError(w, http.StatusInternalServerError, "failed to create challenge")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"challenge": ch,
		"rp_id":     rpid,
		"user":      claims.Subject,
	})
}

func (m *Manager) FinishPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	claims, rpid, ok := m.requireAuthenticatedRPID(w, r)
	if !ok {
		return
	}

	var req struct {
		CredentialID      string `json:"credential_id"`
		Label             string `json:"label"`
		AttestationObject string `json:"attestation_object"`
		ClientDataJSON    string `json:"client_data_json"`
		PublicKeySPKI     string `json:"public_key_spki"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		WriteJSONError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if strings.TrimSpace(req.CredentialID) == "" || req.AttestationObject == "" || req.ClientDataJSON == "" {
		WriteJSONError(w, http.StatusBadRequest, "credential_id, attestation_object, and client_data_json are required")
		return
	}

	attObjBytes, err1 := base64.RawURLEncoding.DecodeString(req.AttestationObject)
	clientDataBytes, err2 := base64.RawURLEncoding.DecodeString(req.ClientDataJSON)
	if err1 != nil || err2 != nil {
		WriteJSONError(w, http.StatusBadRequest, "malformed base64url registration fields")
		return
	}

	if status, msg := m.verifyWebAuthnClientData(clientDataBytes, "webauthn.create", rpid, "register", claims.Subject, http.StatusBadRequest, "invalid or expired challenge"); status != 0 {
		WriteJSONError(w, status, msg)
		return
	}

	att, err := parseAndVerifyAttestationObject(attObjBytes, rpid)
	if err != nil {
		WriteJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	attCredIDB64 := base64.RawURLEncoding.EncodeToString(att.CredentialID)
	if attCredIDB64 != req.CredentialID {
		WriteJSONError(w, http.StatusBadRequest, "credential_id does not match attested credential ID")
		return
	}
	attestedSPKIB64 := base64.RawURLEncoding.EncodeToString(att.PublicKeySPKI)
	if req.PublicKeySPKI != "" && req.PublicKeySPKI != attestedSPKIB64 {
		WriteJSONError(w, http.StatusBadRequest, "public_key_spki does not match attested COSE key")
		return
	}

	label := strings.TrimSpace(req.Label)
	if label == "" {
		label = claims.Subject
	}
	if label == "" {
		label = "Passkey"
	}

	m.mu.Lock()
	var conflict bool
	saveErr := m.withFileLock(func() error {
		if err := m.loadStateFromDiskLocked(); err != nil {
			return err
		}
		for _, pk := range m.state.Passkeys {
			if pk.CredentialID == req.CredentialID {
				conflict = true
				return nil
			}
		}
		m.state.Passkeys = append(m.state.Passkeys, PasskeyCredential{
			CredentialID:  req.CredentialID,
			Label:         label,
			PublicKeySPKI: attestedSPKIB64,
			SignCount:     att.SignCount,
			CreatedAt:     time.Now().UTC(),
		})
		return m.saveStateLocked()
	})
	m.mu.Unlock()

	if saveErr != nil {
		WriteJSONError(w, http.StatusInternalServerError, "failed to persist passkey credential")
		return
	}
	if conflict {
		WriteJSONError(w, http.StatusConflict, "passkey credential_id already registered")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "registered", "credential_id": req.CredentialID})
}

func (m *Manager) BeginPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	rpid, ok := m.requireOriginAndRPID(w, r)
	if !ok {
		return
	}
	ch, err := m.newChallengeFor("login", "")
	if err != nil {
		if errors.Is(err, errTooManyChallenges) {
			WriteJSONError(w, http.StatusTooManyRequests, err.Error())
			return
		}
		WriteJSONError(w, http.StatusInternalServerError, "failed to create challenge")
		return
	}
	m.mu.Lock()
	var credIDs []string
	for _, pk := range m.state.Passkeys {
		credIDs = append(credIDs, pk.CredentialID)
	}
	m.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"challenge":         ch,
		"rp_id":             rpid,
		"allow_credentials": credIDs,
	})
}

func (m *Manager) FinishPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	rpid, ok := m.requireOriginAndRPID(w, r)
	if !ok {
		return
	}

	var req struct {
		CredentialID      string `json:"credential_id"`
		AuthenticatorData string `json:"authenticator_data"`
		ClientDataJSON    string `json:"client_data_json"`
		Signature         string `json:"signature"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		WriteJSONError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.CredentialID == "" {
		WriteJSONError(w, http.StatusUnauthorized, "unknown passkey credential")
		return
	}

	m.mu.Lock()
	var matched *PasskeyCredential
	for i := range m.state.Passkeys {
		if m.state.Passkeys[i].CredentialID == req.CredentialID {
			cp := m.state.Passkeys[i]
			matched = &cp
			break
		}
	}
	m.mu.Unlock()
	if matched == nil {
		WriteJSONError(w, http.StatusUnauthorized, "unknown passkey credential")
		return
	}

	authData, err1 := base64.RawURLEncoding.DecodeString(req.AuthenticatorData)
	clientDataBytes, err2 := base64.RawURLEncoding.DecodeString(req.ClientDataJSON)
	sigBytes, err3 := base64.RawURLEncoding.DecodeString(req.Signature)
	if err1 != nil || err2 != nil || err3 != nil {
		WriteJSONError(w, http.StatusBadRequest, "malformed base64url assertion fields")
		return
	}

	if status, msg := m.verifyWebAuthnClientData(clientDataBytes, "webauthn.get", rpid, "login", "", http.StatusUnauthorized, "invalid or expired WebAuthn challenge"); status != 0 {
		WriteJSONError(w, status, msg)
		return
	}
	if len(authData) < 37 {
		WriteJSONError(w, http.StatusBadRequest, "invalid authenticatorData length")
		return
	}
	expectedRPIDHash := sha256.Sum256([]byte(rpid))
	if !hmac.Equal(authData[:32], expectedRPIDHash[:]) {
		WriteJSONError(w, http.StatusBadRequest, "RP ID hash mismatch")
		return
	}
	if (authData[32] & 0x01) == 0 {
		WriteJSONError(w, http.StatusBadRequest, "User Presence flag not set")
		return
	}

	spkiBytes, err := base64.RawURLEncoding.DecodeString(matched.PublicKeySPKI)
	if err != nil {
		WriteJSONError(w, http.StatusInternalServerError, "corrupt stored public key")
		return
	}
	pubAny, err := x509.ParsePKIXPublicKey(spkiBytes)
	if err != nil {
		WriteJSONError(w, http.StatusInternalServerError, "corrupt stored public key")
		return
	}
	ecPub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		WriteJSONError(w, http.StatusInternalServerError, "corrupt stored public key")
		return
	}

	clientHash := sha256.Sum256(clientDataBytes)
	signedData := append(append([]byte{}, authData...), clientHash[:]...)
	digest := sha256.Sum256(signedData)

	if !ecdsa.VerifyASN1(ecPub, digest[:], sigBytes) {
		WriteJSONError(w, http.StatusUnauthorized, "passkey signature verification failed")
		return
	}

	// Verify monotonic signCount to detect cloned authenticators (WebAuthn §7.2 step 21)
	sigCount := binary.BigEndian.Uint32(authData[33:37])
	var clonedErr bool
	var persistErr error
	m.mu.Lock()
	persistErr = m.withFileLock(func() error {
		if err := m.loadStateFromDiskLocked(); err != nil {
			return err
		}
		for i := range m.state.Passkeys {
			if m.state.Passkeys[i].CredentialID == matched.CredentialID {
				storedCount := m.state.Passkeys[i].SignCount
				if sigCount != 0 || storedCount != 0 {
					if sigCount <= storedCount {
						clonedErr = true
						return nil
					}
					m.state.Passkeys[i].SignCount = sigCount
					return m.saveStateLocked()
				}
				break
			}
		}
		return nil
	})
	m.mu.Unlock()

	if clonedErr {
		WriteJSONError(w, http.StatusUnauthorized, "passkey sign counter regression detected")
		return
	}
	if persistErr != nil {
		WriteJSONError(w, http.StatusInternalServerError, "failed to update passkey sign counter")
		return
	}

	if err := m.IssueSessionCookie(w, matched.Label, "passkey"); err != nil {
		WriteJSONError(w, http.StatusInternalServerError, "failed to issue session cookie")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "authenticated", "method": "passkey", "subject": matched.Label})
}
