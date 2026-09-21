// The P-256 point decoder for the Go lane. `crypto/ecdh` and `crypto/x509`
// both refuse a 33-byte SEC 1 compressed point, so the probe recovers the
// matching `04 || X || Y` encoding here and hands that to the same library
// import, which still validates the point before any key agreement.
//
// It follows the decoding sketch in
// `../../../../docs/spec-proposal--compact-ecdh-envelope.md` line for line, over
// `math/big`, and rejects everything that sketch rejects.
package main

import (
	"errors"
	"math/big"
)

// The P-256 field prime and the curve coefficient b. The a coefficient is -3,
// which is why the curve equation below subtracts 3x rather than carrying a.
var (
	fieldPrime, _ = new(big.Int).SetString(
		"ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
	curveB, _ = new(big.Int).SetString(
		"5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
	three = big.NewInt(3)
)

// decodeCompressedP256 returns the 65-byte uncompressed encoding of the point a
// 33-byte SEC 1 compressed encoding names.
func decodeCompressedP256(encoded []byte) ([]byte, error) {
	if len(encoded) != 33 {
		return nil, errors.New("a compressed P-256 point is 33 bytes")
	}
	prefix := encoded[0]
	if prefix != 0x02 && prefix != 0x03 {
		return nil, errors.New("a compressed P-256 point starts with 0x02 or 0x03")
	}

	x := new(big.Int).SetBytes(encoded[1:])
	if x.Cmp(fieldPrime) >= 0 {
		return nil, errors.New("the x-coordinate is not below the field prime")
	}

	// rhs = x^3 - 3x + b mod p
	rhs := new(big.Int).Mul(x, x)
	rhs.Mod(rhs, fieldPrime)
	rhs.Mul(rhs, x)
	rhs.Sub(rhs, new(big.Int).Mul(three, x))
	rhs.Add(rhs, curveB)
	rhs.Mod(rhs, fieldPrime)

	// p is 3 mod 4, so the square root candidate is rhs^((p+1)/4) mod p. The
	// code can tell whether rhs was a square at all only by squaring it back.
	exponent := new(big.Int).Add(fieldPrime, big.NewInt(1))
	exponent.Rsh(exponent, 2)
	y := new(big.Int).Exp(rhs, exponent, fieldPrime)
	if new(big.Int).Mod(new(big.Int).Mul(y, y), fieldPrime).Cmp(rhs) != 0 {
		return nil, errors.New("the curve equation has no square root mod p for this x-coordinate")
	}

	if y.Bit(0) != uint(prefix&1) {
		y.Sub(fieldPrime, y)
	}
	if y.Cmp(fieldPrime) >= 0 || y.Bit(0) != uint(prefix&1) {
		return nil, errors.New("no y-coordinate with the prefix parity")
	}

	out := make([]byte, 65)
	out[0] = 0x04
	x.FillBytes(out[1:33])
	y.FillBytes(out[33:])
	return out, nil
}
