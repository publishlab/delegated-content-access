// Package primitives holds the standard-library crypto calls the operation
// bridge, `package main` at `go/v1/bridge`, makes: JWK-to-key conversion, the
// AES-GCM carrier, one HKDF-SHA-256 expansion, and RSA private-key import. One
// implementation, so a mistake cannot hide in a second copy.
//
// Nothing here reads a wire protocol, a request, a batch or a refusal code.
// This file imports keys and calls primitives; `bridge.go` decides what a
// failure means for its own answer.
package primitives

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
)

// ---- base64url, unpadded -----------------------------------------------------

func B64u(s string) []byte {
	out, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return nil
	}
	return out
}

func B64uEnc(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// Pad32 left-pads a big-endian scalar or coordinate to the 32 octets P-256
// carries. It widens and never narrows: 33 octets is not a P-256 value with a
// leading octet to drop, it is a different number, and reshaping `0xFF || d` to
// its last 32 octets imports a JWK that PHP refuses and WebCrypto cannot read.
// This package exists to catch a runtime that accepts a key the others reject.
// An over-wide input has no answer, so Pad32 returns nil and every caller below
// refuses the key.
func Pad32(b []byte) []byte {
	if len(b) > 32 {
		return nil
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// ---- JWK ---------------------------------------------------------------------

// JWK is RFC 7517 form, read exactly as the corpus records it: `kty`, `crv`
// and the base64url coordinates `x` and `y`, with `d` on a private one. A
// caller hands one of these straight to the functions below, which are this
// runtime's own key routines. Nothing here reads `kty` or `crv` to decide what
// to do; a caller that wants that check makes it.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	D   string `json:"d"`
}

// PointFromJWK builds the 65-octet uncompressed SEC 1 point 0x04 || X || Y,
// each coordinate at its full 32-octet width. A coordinate wider than 32 octets
// names no point on this curve, so PointFromJWK returns nil rather than a point
// built from a reshaped one, and ECDHCurve.NewPublicKey then refuses it.
func PointFromJWK(j JWK) []byte {
	x, y := Pad32(B64u(j.X)), Pad32(B64u(j.Y))
	if x == nil || y == nil {
		return nil
	}
	out := make([]byte, 0, 65)
	out = append(out, 0x04)
	out = append(out, x...)
	out = append(out, y...)
	return out
}

// ECDHCurve is P-256, the only curve this bridge uses.
var ECDHCurve = ecdh.P256()

// ECDHPrivateFromJWK imports one EC-P256 private JWK by its `d` scalar.
func ECDHPrivateFromJWK(j JWK) (*ecdh.PrivateKey, error) {
	d := Pad32(B64u(j.D))
	if d == nil {
		return nil, fmt.Errorf("jwk d is wider than the 32 octets a P-256 scalar carries")
	}
	return ECDHCurve.NewPrivateKey(d)
}

// HKDF runs one HKDF-SHA-256 invocation (RFC 5869) with an empty salt over the
// given input keying material and info octets, and returns width octets.
//
// crypto/hkdf takes info as a string. A Go string holds arbitrary octets, so
// string(info) passes a 0x00 or an octet above 0x7f to the derivation
// unchanged.
func HKDF(ikm []byte, info []byte, width int) ([]byte, error) {
	return hkdf.Key(sha256.New, ikm, nil, string(info), width)
}

// ---- AES-GCM -----------------------------------------------------------------

// GCMSeal returns the ciphertext with the 16-octet tag appended, or nil on an
// error, including a nonce that is not the cipher's nonce size. A 16-octet key
// selects AES-128-GCM and a 32-octet key AES-256-GCM; aes.NewCipher makes that
// choice.
func GCMSeal(key, nonce, plaintext, aad []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}
	if len(nonce) != g.NonceSize() {
		return nil
	}
	return g.Seal(nil, nonce, plaintext, aad)
}

// GCMOpen takes ciphertext||tag directly and returns the plaintext, or nil on a
// tag failure or a nonce that is not the cipher's nonce size. Go's Open reads
// the trailing 16 octets itself, so no caller splits them off.
func GCMOpen(key, nonce, ctAndTag, aad []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}
	if len(nonce) != g.NonceSize() {
		return nil
	}
	pt, err := g.Open(nil, nonce, ctAndTag, aad)
	if err != nil {
		return nil
	}
	return pt
}

// ---- RSA -----------------------------------------------------------------

// RSAJWK is the RSA private-key member set the corpus records: `kty`, the
// public `n` and `e`, and the private `d`, `p` and `q`. Precompute below
// recomputes `dp`, `dq` and `qi`, so this struct leaves them out.
type RSAJWK struct {
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
	D   string `json:"d"`
	P   string `json:"p"`
	Q   string `json:"q"`
}

// RSAPrivateFromJWK builds a crypto/rsa private key from an RSAJWK, refusing a
// public exponent outside the range crypto/rsa accepts.
func RSAPrivateFromJWK(j RSAJWK) (*rsa.PrivateKey, error) {
	if j.Kty != "RSA" {
		return nil, fmt.Errorf("kty %q, not RSA", j.Kty)
	}
	e := bigFromB64u(j.E)
	if !e.IsInt64() || e.Int64() < 3 || e.Int64() > (1<<31-1) {
		return nil, fmt.Errorf("public exponent out of range")
	}
	priv := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: bigFromB64u(j.N), E: int(e.Int64())},
		D:         bigFromB64u(j.D),
		Primes:    []*big.Int{bigFromB64u(j.P), bigFromB64u(j.Q)},
	}
	if err := priv.Validate(); err != nil {
		return nil, err
	}
	priv.Precompute()
	return priv, nil
}

func bigFromB64u(s string) *big.Int { return new(big.Int).SetBytes(B64u(s)) }
