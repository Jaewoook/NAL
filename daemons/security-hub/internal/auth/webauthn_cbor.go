package auth

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

type cborReader struct {
	data []byte
	pos  int
}

func (r *cborReader) readByte() (byte, error) {
	if r.pos >= len(r.data) {
		return 0, errors.New("unexpected end of CBOR input")
	}
	b := r.data[r.pos]
	r.pos++
	return b, nil
}

func (r *cborReader) readUintArg(ai byte) (uint64, error) {
	if ai < 24 {
		return uint64(ai), nil
	}
	switch ai {
	case 24:
		b, err := r.readByte()
		return uint64(b), err
	case 25:
		if r.pos+2 > len(r.data) {
			return 0, errors.New("truncated CBOR uint16")
		}
		v := binary.BigEndian.Uint16(r.data[r.pos : r.pos+2])
		r.pos += 2
		return uint64(v), nil
	case 26:
		if r.pos+4 > len(r.data) {
			return 0, errors.New("truncated CBOR uint32")
		}
		v := binary.BigEndian.Uint32(r.data[r.pos : r.pos+4])
		r.pos += 4
		return uint64(v), nil
	case 27:
		if r.pos+8 > len(r.data) {
			return 0, errors.New("truncated CBOR uint64")
		}
		v := binary.BigEndian.Uint64(r.data[r.pos : r.pos+8])
		r.pos += 8
		return v, nil
	default:
		return 0, errors.New("unsupported CBOR indefinite or reserved length")
	}
}

func (r *cborReader) readValue(depth int) (any, error) {
	if depth > 8 {
		return nil, errors.New("CBOR nesting depth exceeded")
	}
	hdr, err := r.readByte()
	if err != nil {
		return nil, err
	}
	major := hdr >> 5
	ai := hdr & 0x1f

	switch major {
	case 0: // unsigned int
		u, err := r.readUintArg(ai)
		if err != nil {
			return nil, err
		}
		if u > uint64(1<<62) {
			return nil, errors.New("CBOR integer overflow")
		}
		return int64(u), nil
	case 1: // negative int (-1 - n)
		u, err := r.readUintArg(ai)
		if err != nil {
			return nil, err
		}
		if u > uint64(1<<62) {
			return nil, errors.New("CBOR negative integer overflow")
		}
		return -1 - int64(u), nil
	case 2: // byte string
		n, err := r.readUintArg(ai)
		if err != nil {
			return nil, err
		}
		if n > uint64(len(r.data)-r.pos) {
			return nil, errors.New("truncated CBOR byte string")
		}
		out := append([]byte(nil), r.data[r.pos:r.pos+int(n)]...)
		r.pos += int(n)
		return out, nil
	case 3: // text string
		n, err := r.readUintArg(ai)
		if err != nil {
			return nil, err
		}
		if n > uint64(len(r.data)-r.pos) {
			return nil, errors.New("truncated CBOR text string")
		}
		out := string(r.data[r.pos : r.pos+int(n)])
		r.pos += int(n)
		return out, nil
	case 4: // array
		n, err := r.readUintArg(ai)
		if err != nil {
			return nil, err
		}
		if n > 256 {
			return nil, errors.New("CBOR array too large")
		}
		arr := make([]any, 0, int(n))
		for i := 0; i < int(n); i++ {
			v, err := r.readValue(depth + 1)
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
		}
		return arr, nil
	case 5: // map
		n, err := r.readUintArg(ai)
		if err != nil {
			return nil, err
		}
		if n > 256 {
			return nil, errors.New("CBOR map too large")
		}
		m := make(map[any]any, int(n))
		for i := 0; i < int(n); i++ {
			k, err := r.readValue(depth + 1)
			if err != nil {
				return nil, err
			}
			switch k.(type) {
			case int64, string, bool, nil:
			default:
				return nil, fmt.Errorf("unsupported CBOR map key type %T", k)
			}
			v, err := r.readValue(depth + 1)
			if err != nil {
				return nil, err
			}
			m[k] = v
		}
		return m, nil
	case 7: // simple/float (boolean/null in attStmt)
		switch ai {
		case 20:
			return false, nil
		case 21:
			return true, nil
		case 22, 23:
			return nil, nil
		default:
			_, err := r.readUintArg(ai)
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported CBOR major type %d", major)
	}
}

type parsedAttestation struct {
	CredentialID  []byte
	SignCount     uint32
	PublicKeySPKI []byte
}

func parseAndVerifyAttestationObject(rawAttObj []byte, rpid string) (*parsedAttestation, error) {
	if len(rawAttObj) == 0 {
		return nil, errors.New("empty attestationObject")
	}
	rd := &cborReader{data: rawAttObj}
	topAny, err := rd.readValue(0)
	if err != nil {
		return nil, fmt.Errorf("invalid attestationObject CBOR: %w", err)
	}
	topMap, ok := topAny.(map[any]any)
	if !ok {
		return nil, errors.New("attestationObject must be a CBOR map")
	}
	authDataAny, ok := topMap["authData"]
	if !ok {
		return nil, errors.New("attestationObject missing authData")
	}
	authData, ok := authDataAny.([]byte)
	if !ok {
		return nil, errors.New("attestationObject authData must be bytes")
	}
	// Minimum length: 32 (rpIdHash) + 1 (flags) + 4 (signCount) + 16 (aaguid) + 2 (credIdLen) = 55
	if len(authData) < 55 {
		return nil, errors.New("attested authenticatorData too short")
	}
	expectedRPIDHash := sha256.Sum256([]byte(rpid))
	if !hmac.Equal(authData[:32], expectedRPIDHash[:]) {
		return nil, errors.New("attestation RP ID hash mismatch")
	}
	flags := authData[32]
	if (flags & 0x01) == 0 {
		return nil, errors.New("attestation User Presence flag not set")
	}
	if (flags & 0x40) == 0 {
		return nil, errors.New("attestation Attested Credential Data flag not set")
	}

	signCount := binary.BigEndian.Uint32(authData[33:37])
	credIDLen := int(binary.BigEndian.Uint16(authData[53:55]))
	if credIDLen == 0 || 55+credIDLen >= len(authData) {
		return nil, errors.New("invalid credentialId length in authData")
	}
	credID := append([]byte(nil), authData[55:55+credIDLen]...)
	coseBytes := authData[55+credIDLen:]

	coseReader := &cborReader{data: coseBytes}
	coseAny, err := coseReader.readValue(0)
	if err != nil {
		return nil, fmt.Errorf("invalid COSE public key CBOR: %w", err)
	}
	if (flags & 0x80) != 0 {
		extAny, extErr := coseReader.readValue(0)
		if extErr != nil {
			return nil, fmt.Errorf("invalid WebAuthn extensions CBOR: %w", extErr)
		}
		if _, ok := extAny.(map[any]any); !ok {
			return nil, errors.New("WebAuthn extensions must be a CBOR map")
		}
	}
	if coseReader.pos != len(coseBytes) {
		return nil, errors.New("unexpected trailing bytes after COSE public key")
	}
	coseMap, ok := coseAny.(map[any]any)
	if !ok {
		return nil, errors.New("COSE public key must be a CBOR map")
	}

	kty, okK := coseMap[int64(1)].(int64)
	alg, okA := coseMap[int64(3)].(int64)
	crv, okC := coseMap[int64(-1)].(int64)
	xBytes, okX := coseMap[int64(-2)].([]byte)
	yBytes, okY := coseMap[int64(-3)].([]byte)
	if !okK || !okA || !okC || !okX || !okY {
		return nil, errors.New("incomplete COSE EC2 P-256 public key fields")
	}
	if kty != 2 || alg != -7 || crv != 1 {
		return nil, fmt.Errorf("unsupported COSE key parameters kty=%d alg=%d crv=%d (expected EC2/ES256/P-256)", kty, alg, crv)
	}
	if len(xBytes) != 32 || len(yBytes) != 32 {
		return nil, errors.New("invalid P-256 coordinate byte length")
	}

	// Validate point lies on P-256 using crypto/ecdh (uncompressed SEC1 point 0x04 || X || Y)
	sec1 := make([]byte, 1+32+32)
	sec1[0] = 0x04
	copy(sec1[1:33], xBytes)
	copy(sec1[33:65], yBytes)
	if _, err := ecdh.P256().NewPublicKey(sec1); err != nil {
		return nil, fmt.Errorf("invalid P-256 public key point: %w", err)
	}

	ecPub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}
	spkiBytes, err := x509.MarshalPKIXPublicKey(ecPub)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SPKI public key: %w", err)
	}

	return &parsedAttestation{
		CredentialID:  credID,
		SignCount:     signCount,
		PublicKeySPKI: spkiBytes,
	}, nil
}
