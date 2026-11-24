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
	"math/big"
	"strings"
	"time"
)

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

type idTokenClaims struct {
	Iss               string `json:"iss"`
	Aud               any    `json:"aud"`
	Azp               string `json:"azp"`
	Nonce             string `json:"nonce"`
	Exp               int64  `json:"exp"`
	Nbf               int64  `json:"nbf"`
	PreferredUsername string `json:"preferred_username"`
	Nickname          string `json:"nickname"`
	Name              string `json:"name"`
	Email             string `json:"email"`
	Sub               string `json:"sub"`
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

func extractUsernameFromClaims(claims idTokenClaims) string {
	if claims.PreferredUsername != "" {
		return claims.PreferredUsername
	}
	if claims.Nickname != "" {
		return claims.Nickname
	}
	if claims.Email != "" {
		parts := strings.Split(claims.Email, "@")
		return parts[0]
	}
	if claims.Name != "" {
		return claims.Name
	}
	return claims.Sub
}

func (m *Manager) verifyAndExtractIDToken(ctx context.Context, jwt string, expectedNonce string) (string, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return "", errors.New("malformed JWT: expected 3 segments")
	}
	if err := m.verifyJWTSignature(ctx, parts[0], parts[1], parts[2]); err != nil {
		return "", err
	}

	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("failed to decode JWT payload: %w", err)
	}
	var claims idTokenClaims
	if err := json.Unmarshal(raw, &claims); err != nil {
		return "", fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	now := time.Now().UTC().Unix()
	if claims.Exp <= 0 {
		return "", errors.New("ID token missing exp claim")
	}
	if now > (claims.Exp + 60) {
		return "", errors.New("ID token is expired")
	}
	if claims.Nbf > 0 && now < (claims.Nbf-60) {
		return "", errors.New("ID token not yet valid (nbf)")
	}

	if m.cfg.OIDCIssuer != "" {
		if claims.Iss == "" {
			return "", errors.New("ID token missing iss claim")
		}
		expURL, err1 := validateHTTPSURL(m.cfg.OIDCIssuer)
		actURL, err2 := validateHTTPSURL(claims.Iss)
		if err1 != nil || err2 != nil ||
			!strings.EqualFold(expURL.Scheme, actURL.Scheme) ||
			!strings.EqualFold(expURL.Host, actURL.Host) ||
			normalizeIssuerPath(expURL.Path) != normalizeIssuerPath(actURL.Path) {
			return "", fmt.Errorf("issuer mismatch: expected %q, got %q", m.cfg.OIDCIssuer, claims.Iss)
		}
	}

	if expectedNonce != "" {
		if claims.Nonce == "" || !hmac.Equal([]byte(claims.Nonce), []byte(expectedNonce)) {
			return "", errors.New("ID token nonce mismatch")
		}
	}

	if m.cfg.OIDCClientID != "" {
		if claims.Aud == nil {
			return "", errors.New("ID token missing aud claim")
		}
		var audMatched bool
		var audMulti bool
		switch a := claims.Aud.(type) {
		case string:
			audMatched = (a == m.cfg.OIDCClientID)
		case []any:
			audMulti = len(a) > 1
			for _, item := range a {
				if s, ok := item.(string); ok && s == m.cfg.OIDCClientID {
					audMatched = true
					break
				}
			}
		}
		if !audMatched {
			return "", fmt.Errorf("audience mismatch: token does not match client ID %q", m.cfg.OIDCClientID)
		}
		if audMulti {
			if claims.Azp == "" || claims.Azp != m.cfg.OIDCClientID {
				return "", fmt.Errorf("authorized party (azp) mismatch for multi-audience token: got %q, want %q", claims.Azp, m.cfg.OIDCClientID)
			}
		} else if claims.Azp != "" && claims.Azp != m.cfg.OIDCClientID {
			return "", fmt.Errorf("authorized party (azp) mismatch: got %q, want %q", claims.Azp, m.cfg.OIDCClientID)
		}
	}

	return extractUsernameFromClaims(claims), nil
}

func extractUsernameFromJWT(jwt string) string {
	parts := strings.Split(jwt, ".")
	if len(parts) < 2 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims idTokenClaims
	if err := json.Unmarshal(raw, &claims); err != nil {
		return ""
	}
	return extractUsernameFromClaims(claims)
}
