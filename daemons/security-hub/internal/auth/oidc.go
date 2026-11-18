package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type oidcDiscoveryDoc struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	// RSA
	N string `json:"n"`
	E string `json:"e"`
	// EC
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

func validateHTTPSURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("URL is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid URL %q: %w", raw, err)
	}
	if !strings.EqualFold(u.Scheme, "https") || u.Host == "" {
		return nil, fmt.Errorf("URL %q must use https:// scheme", raw)
	}
	return u, nil
}

func normalizeIssuerPath(p string) string {
	return strings.TrimRight(p, "/")
}

func (m *Manager) oidcFallbackEndpoints(issuer string) (authURL, tokenURL, jwksURL string) {
	trimmed := strings.TrimRight(issuer, "/")
	authURL = trimmed + "/authorize/"
	tokenURL = trimmed + "/token/"
	jwksURL = trimmed + "/jwks/"
	if strings.Contains(trimmed, "/application/o/") {
		parts := strings.Split(trimmed, "/application/o/")
		authURL = parts[0] + "/application/o/authorize/"
		tokenURL = parts[0] + "/application/o/token/"
		// Authentik exposes per-application JWKS at <issuer>/jwks/
		jwksURL = trimmed + "/jwks/"
	}
	return authURL, tokenURL, jwksURL
}

func (m *Manager) discoverOIDC(ctx context.Context) (oidcDiscoveryDoc, error) {
	issURL, err := validateHTTPSURL(m.cfg.OIDCIssuer)
	if err != nil {
		return oidcDiscoveryDoc{}, err
	}

	m.oidcMu.Lock()
	if m.oidcDoc != nil && time.Since(m.oidcDocFetched) < 10*time.Minute && m.oidcDocIssuer == m.cfg.OIDCIssuer {
		doc := *m.oidcDoc
		m.oidcMu.Unlock()
		return doc, nil
	}
	m.oidcMu.Unlock()

	wellKnown := strings.TrimRight(issURL.String(), "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return oidcDiscoveryDoc{}, err
	}
	resp, err := m.safeHTTPClient().Do(req)
	if err != nil {
		return oidcDiscoveryDoc{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return oidcDiscoveryDoc{}, fmt.Errorf("OIDC discovery returned HTTP %d", resp.StatusCode)
	}
	var doc oidcDiscoveryDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return oidcDiscoveryDoc{}, err
	}
	if doc.AuthorizationEndpoint != "" {
		if _, err := validateHTTPSURL(doc.AuthorizationEndpoint); err != nil {
			return oidcDiscoveryDoc{}, err
		}
	}
	if doc.TokenEndpoint != "" {
		if _, err := validateHTTPSURL(doc.TokenEndpoint); err != nil {
			return oidcDiscoveryDoc{}, err
		}
	}
	if doc.JWKSURI != "" {
		if _, err := validateHTTPSURL(doc.JWKSURI); err != nil {
			return oidcDiscoveryDoc{}, err
		}
	}

	m.oidcMu.Lock()
	m.oidcDoc = &doc
	m.oidcDocIssuer = m.cfg.OIDCIssuer
	m.oidcDocFetched = time.Now()
	m.oidcMu.Unlock()
	return doc, nil
}

func (m *Manager) fetchJWKS(ctx context.Context, jwksURI string, forceRefresh bool) ([]jwkKey, error) {
	if _, err := validateHTTPSURL(jwksURI); err != nil {
		return nil, err
	}
	m.oidcMu.Lock()
	if !forceRefresh && len(m.jwksKeys) > 0 && time.Since(m.jwksFetched) < 10*time.Minute && m.jwksURI == jwksURI {
		keys := append([]jwkKey(nil), m.jwksKeys...)
		m.oidcMu.Unlock()
		return keys, nil
	}
	m.oidcMu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, err
	}
	resp, err := m.safeHTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned HTTP %d", resp.StatusCode)
	}
	var payload struct {
		Keys []jwkKey `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&payload); err != nil {
		return nil, err
	}
	if len(payload.Keys) == 0 {
		return nil, errors.New("JWKS endpoint returned zero keys")
	}

	m.oidcMu.Lock()
	m.jwksKeys = payload.Keys
	m.jwksURI = jwksURI
	m.jwksFetched = time.Now()
	m.oidcMu.Unlock()
	return payload.Keys, nil
}

func (m *Manager) resolveJWKSURI(ctx context.Context) (string, error) {
	if doc, err := m.discoverOIDC(ctx); err == nil && doc.JWKSURI != "" {
		return doc.JWKSURI, nil
	}
	_, _, fallbackJWKS := m.oidcFallbackEndpoints(m.cfg.OIDCIssuer)
	if _, err := validateHTTPSURL(fallbackJWKS); err != nil {
		return "", err
	}
	return fallbackJWKS, nil
}

func hashSpecForAlg(alg string) (crypto.Hash, func() hash.Hash, error) {
	switch alg {
	case "RS256", "ES256", "HS256":
		return crypto.SHA256, sha256.New, nil
	case "RS384", "ES384", "HS384":
		return crypto.SHA384, sha512.New384, nil
	case "RS512", "ES512", "HS512":
		return crypto.SHA512, sha512.New, nil
	default:
		return 0, nil, fmt.Errorf("unsupported JWT signing algorithm %q", alg)
	}
}

func verifySignatureWithJWK(key jwkKey, alg string, signingInput, sig []byte) error {
	if key.Use != "" && key.Use != "sig" {
		return errors.New("JWK key is not marked for signature verification")
	}
	if key.Alg != "" && key.Alg != alg {
		return fmt.Errorf("JWK alg %q does not match JWT header alg %q", key.Alg, alg)
	}
	hashAlg, newHash, err := hashSpecForAlg(alg)
	if err != nil {
		return err
	}
	h := newHash()
	_, _ = h.Write(signingInput)
	digest := h.Sum(nil)

	switch {
	case strings.HasPrefix(alg, "RS"):
		if key.Kty != "RSA" {
			return fmt.Errorf("key type %q mismatch for %s", key.Kty, alg)
		}
		nBytes, err1 := base64.RawURLEncoding.DecodeString(key.N)
		eBytes, err2 := base64.RawURLEncoding.DecodeString(key.E)
		if err1 != nil || err2 != nil || len(nBytes) == 0 || len(eBytes) == 0 {
			return errors.New("malformed RSA JWK")
		}
		var eInt int
		for _, b := range eBytes {
			eInt = (eInt << 8) | int(b)
		}
		if eInt < 3 {
			return errors.New("invalid RSA exponent")
		}
		pub := &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: eInt,
		}
		if pub.N.BitLen() < 2048 {
			return errors.New("RSA JWK key size below 2048 bits")
		}
		return rsa.VerifyPKCS1v15(pub, hashAlg, digest, sig)

	case strings.HasPrefix(alg, "ES"):
		if key.Kty != "EC" {
			return fmt.Errorf("key type %q mismatch for %s", key.Kty, alg)
		}
		var curve elliptic.Curve
		var coordBytes int
		switch alg {
		case "ES256":
			curve = elliptic.P256()
			coordBytes = 32
			if key.Crv != "P-256" {
				return fmt.Errorf("JWK curve %q mismatch for ES256", key.Crv)
			}
		case "ES384":
			curve = elliptic.P384()
			coordBytes = 48
			if key.Crv != "P-384" {
				return fmt.Errorf("JWK curve %q mismatch for ES384", key.Crv)
			}
		case "ES512":
			curve = elliptic.P521()
			coordBytes = 66
			if key.Crv != "P-521" {
				return fmt.Errorf("JWK curve %q mismatch for ES512", key.Crv)
			}
		}
		xBytes, err1 := base64.RawURLEncoding.DecodeString(key.X)
		yBytes, err2 := base64.RawURLEncoding.DecodeString(key.Y)
		if err1 != nil || err2 != nil || len(xBytes) == 0 || len(yBytes) == 0 {
			return errors.New("malformed EC JWK")
		}
		if len(sig) != 2*coordBytes {
			return errors.New("invalid ECDSA signature length")
		}
		pub := &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(xBytes),
			Y:     new(big.Int).SetBytes(yBytes),
		}
		r := new(big.Int).SetBytes(sig[:coordBytes])
		s := new(big.Int).SetBytes(sig[coordBytes:])
		if !ecdsa.Verify(pub, digest, r, s) {
			return errors.New("ECDSA JWT signature verification failed")
		}
		return nil

	default:
		return fmt.Errorf("unsupported JWK algorithm %q", alg)
	}
}

func (m *Manager) verifyJWTSignature(ctx context.Context, headerB64, payloadB64, sigB64 string) error {
	hdrBytes, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return fmt.Errorf("invalid JWT header encoding: %w", err)
	}
	var hdr jwtHeader
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		return fmt.Errorf("invalid JWT header JSON: %w", err)
	}
	if hdr.Alg == "" || strings.EqualFold(hdr.Alg, "none") {
		return errors.New("JWT alg 'none' or empty alg is rejected")
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil || len(sigBytes) == 0 {
		return errors.New("invalid or missing JWT signature")
	}
	signingInput := []byte(headerB64 + "." + payloadB64)

	if strings.HasPrefix(hdr.Alg, "HS") {
		if m.cfg.OIDCClientSecret == "" {
			return errors.New("HS* ID token rejected without OIDC client secret")
		}
		_, newHash, err := hashSpecForAlg(hdr.Alg)
		if err != nil {
			return err
		}
		mac := hmac.New(newHash, []byte(m.cfg.OIDCClientSecret))
		_, _ = mac.Write(signingInput)
		if !hmac.Equal(mac.Sum(nil), sigBytes) {
			return errors.New("HMAC ID token signature verification failed")
		}
		return nil
	}

	if !strings.HasPrefix(hdr.Alg, "RS") && !strings.HasPrefix(hdr.Alg, "ES") {
		return fmt.Errorf("unsupported JWT algorithm %q", hdr.Alg)
	}

	jwksURI, err := m.resolveJWKSURI(ctx)
	if err != nil {
		return fmt.Errorf("failed to resolve JWKS URI: %w", err)
	}
	keys, err := m.fetchJWKS(ctx, jwksURI, false)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	tryMatch := func(candidateKeys []jwkKey) (matched bool, err error) {
		var lastErr error
		for _, k := range candidateKeys {
			if hdr.Kid != "" && k.Kid != hdr.Kid {
				continue
			}
			matched = true
			if vErr := verifySignatureWithJWK(k, hdr.Alg, signingInput, sigBytes); vErr == nil {
				return true, nil
			} else {
				lastErr = vErr
			}
		}
		if !matched {
			return false, fmt.Errorf("no matching JWK for kid %q", hdr.Kid)
		}
		if lastErr == nil {
			lastErr = errors.New("JWT signature verification failed")
		}
		return true, lastErr
	}

	matched, err := tryMatch(keys)
	if err == nil {
		return nil
	}
	if !matched && hdr.Kid != "" {
		// Key rotation: retry once with fresh JWKS fetch
		refreshedKeys, rErr := m.fetchJWKS(ctx, jwksURI, true)
		if rErr == nil {
			if _, err2 := tryMatch(refreshedKeys); err2 == nil {
				return nil
			} else {
				return err2
			}
		}
	}
	return err
}
