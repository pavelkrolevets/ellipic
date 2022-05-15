package nist

import (
	"crypto/sha256"
	"math/big"

	"github.com/pavelkrolevets/ecdsa/ecgeneric"
)

// Curve params y^2 = x^3 + a*x + b (a=0, b=7), h = 1, p=17
var TinyEc = ecgeneric.CurveParams{
	P:       big.NewInt(17),
	N:       big.NewInt(18),
	A:       big.NewInt(0),
	B:       big.NewInt(7),
	Gx:      big.NewInt(15),
	Gy:      big.NewInt(13),
	BitSize: 18,
	Name:    "p1707",
}

var	Secp256k1 = ecgeneric.CurveParams{
	P:       ecgeneric.BigFromHex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"),
	N:       ecgeneric.BigFromHex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"),
	A:       big.NewInt(0),
	B:       big.NewInt(7),
	Gx:      ecgeneric.BigFromHex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
	Gy:      ecgeneric.BigFromHex("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"),
	BitSize: 256,
	Name:    "secp256k1",
}


func Hash(m []byte) ([32]byte) {
	b := sha256.Sum256(m)
	return b
}

func Sign(m []byte) []byte {
	h := Hash(m)
	
}