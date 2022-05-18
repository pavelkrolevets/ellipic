package nist

import (
	"crypto/sha256"
	"io"
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

var mask = []byte{0xff, 0x1, 0x3, 0x7, 0xf, 0x1f, 0x3f, 0x7f}

func Hash(m []byte) ([32]byte) {
	b := sha256.Sum256(m)
	return b
}

func Sign(private_key *big.Int, m []byte, curve *ecgeneric.CurveParams, rand io.Reader) (r *big.Int, s *big.Int, err error) {
	hash := new(big.Int).SetBytes(m[:])
	N := curve.N
	bitSize := N.BitLen()
	byteLen := (bitSize + 7) / 8
	k := make([]byte, byteLen)
	x := new(big.Int)
	r, s = new(big.Int), new(big.Int)

	for r.Cmp(big.NewInt(0))== 0 && s.Cmp(big.NewInt(0))== 0 {
		_, err := io.ReadFull(rand, k)
		if err != nil {
			return nil, nil, err
		}
		kModInv := new(big.Int).ModInverse(new(big.Int).SetBytes(k[:]), curve.N)
		x, _= curve.ScalarBaseMult(new(big.Int).SetBytes(k[:]))
		r.Set(x.Mod(x, curve.N))
		s.Mul(r, private_key)
		s.Add(hash, s)
		s.Mul(s, kModInv)
		s.Mod(s, curve.N)
	}
	return
}

func Verify(m []byte, r, s, pubX, pubY *big.Int) (bool, error) {
	hash := new(big.Int).SetBytes(m[:]) 
	var w, u1, u2 = new(big.Int), new(big.Int), new(big.Int)
	
	w.ModInverse(s, Secp256k1.N)
	u1.Mul(hash, w)
	u1.Mod(u1, Secp256k1.N)

	u2.Mul(r, w)
	u2.Mod(u2, Secp256k1.N)

	u1gX, u1gY := Secp256k1.ScalarBaseMult(u1)
	u2mulPubX, u2mulPubY := Secp256k1.ScalarMultGeneric(pubX, pubY, u2)
	x, _ := Secp256k1.AddPointsGeneric(u1gX, u1gY, u2mulPubX, u2mulPubY)

	if new(big.Int).Mod(r, Secp256k1.N).Cmp(new(big.Int).Mod(x, Secp256k1.N)) == 0 {
		return true, nil
	} else {
		return false, nil
	}
}