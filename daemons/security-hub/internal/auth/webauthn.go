package auth

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"
)

func (m *Manager) newChallenge() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	ch := base64.RawURLEncoding.EncodeToString(buf)
	m.mu.Lock()
	m.challenges[ch] = time.Now().UTC().Add(5 * time.Minute)
	m.mu.Unlock()
	return ch, nil
}

func (m *Manager) consumeChallenge(ch string) bool {
	if ch == "" {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	exp, ok := m.challenges[ch]
	if !ok {
		return false
	}
	delete(m.challenges, ch)
	return time.Now().UTC().Before(exp)
}

func (m *Manager) BeginPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	claims, err := m.VerifyRequest(r)
	if err != nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	ch, err := m.newChallenge()
	if err != nil {
		http.Error(w, `{"error":"failed to create challenge"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"challenge": ch,
		"rp_id":     m.cfg.RPID,
		"user":      claims.Subject,
	})
}

func (m *Manager) FinishPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	if _, err := m.VerifyRequest(r); err != nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	var req struct {
		CredentialID  string `json:"credential_id"`
		Label         string `json:"label"`
		PublicKeySPKI string `json:"public_key_spki"`
		Challenge     string `json:"challenge"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}
	if !m.consumeChallenge(req.Challenge) {
		http.Error(w, `{"error":"invalid or expired challenge"}`, http.StatusBadRequest)
		return
	}
	spkiBytes, err := base64.RawURLEncoding.DecodeString(req.PublicKeySPKI)
	if err != nil {
		http.Error(w, `{"error":"invalid public_key_spki encoding"}`, http.StatusBadRequest)
		return
	}
	pub, err := x509.ParsePKIXPublicKey(spkiBytes)
	if err != nil {
		http.Error(w, `{"error":"invalid SPKI public key"}`, http.StatusBadRequest)
		return
	}
	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		http.Error(w, `{"error":"expected ECDSA P-256 public key"}`, http.StatusBadRequest)
		return
	}
	if req.Label == "" {
		req.Label = "Passkey"
	}

	m.mu.Lock()
	m.state.Passkeys = append(m.state.Passkeys, PasskeyCredential{
		CredentialID:  req.CredentialID,
		Label:         req.Label,
		PublicKeySPKI: req.PublicKeySPKI,
		CreatedAt:     time.Now().UTC(),
	})
	_ = m.saveStateLocked()
	m.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "registered", "credential_id": req.CredentialID})
}

func (m *Manager) BeginPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	ch, err := m.newChallenge()
	if err != nil {
		http.Error(w, `{"error":"failed to create challenge"}`, http.StatusInternalServerError)
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
		"challenge":          ch,
		"rp_id":              m.cfg.RPID,
		"allow_credentials": credIDs,
	})
}

func (m *Manager) FinishPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CredentialID      string `json:"credential_id"`
		AuthenticatorData string `json:"authenticator_data"`
		ClientDataJSON    string `json:"client_data_json"`
		Signature         string `json:"signature"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
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
		http.Error(w, `{"error":"unknown passkey credential"}`, http.StatusUnauthorized)
		return
	}

	authData, err1 := base64.RawURLEncoding.DecodeString(req.AuthenticatorData)
	clientDataBytes, err2 := base64.RawURLEncoding.DecodeString(req.ClientDataJSON)
	sigBytes, err3 := base64.RawURLEncoding.DecodeString(req.Signature)
	if err1 != nil || err2 != nil || err3 != nil {
		http.Error(w, `{"error":"malformed base64url assertion fields"}`, http.StatusBadRequest)
		return
	}

	var clientData struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(clientDataBytes, &clientData); err != nil {
		http.Error(w, `{"error":"invalid clientDataJSON"}`, http.StatusBadRequest)
		return
	}
	if !m.consumeChallenge(clientData.Challenge) {
		http.Error(w, `{"error":"invalid or expired WebAuthn challenge"}`, http.StatusUnauthorized)
		return
	}

	spkiBytes, _ := base64.RawURLEncoding.DecodeString(matched.PublicKeySPKI)
	pubAny, err := x509.ParsePKIXPublicKey(spkiBytes)
	if err != nil {
		http.Error(w, `{"error":"corrupt stored public key"}`, http.StatusInternalServerError)
		return
	}
	ecPub := pubAny.(*ecdsa.PublicKey)

	clientHash := sha256.Sum256(clientDataBytes)
	signedData := append(append([]byte{}, authData...), clientHash[:]...)
	digest := sha256.Sum256(signedData)

	if !ecdsa.VerifyASN1(ecPub, digest[:], sigBytes) {
		http.Error(w, `{"error":"passkey signature verification failed"}`, http.StatusUnauthorized)
		return
	}

	_ = m.IssueSessionCookie(w, matched.Label, "passkey")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "authenticated", "method": "passkey", "subject": matched.Label})
}
