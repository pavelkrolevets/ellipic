package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/big"

	"golang.org/x/crypto/sha3"
)

// CurveParams contains the parameters of an elliptic curve and also provides
// a generic, non-constant time implementation of Curve.
type CurveParams struct {
	P       *big.Int // the order of the underlying field
	N       *big.Int // the order of the base point
	A       *big.Int // the constant of the curve equation
	B       *big.Int // the constant of the curve equation
	Gx, Gy  *big.Int // (x,y) of the base point
	BitSize int      // the size of the underlying field
	Name    string   // the canonical name of the curve
}

func main() {
	m_b := []byte("Hello signature!")
	h_m_b := sha3.New256()
	h_m_b.Write(m_b)
	fmt.Println(hex.EncodeToString(h_m_b.Sum(nil)))

	// Curve params y^2 = x^3 + a*x + b (a=0, b=7), h = 1, p=17
	tiny_ec := CurveParams{
		P:       big.NewInt(17),
		N:       big.NewInt(18),
		A:       big.NewInt(0),
		B:       big.NewInt(7),
		Gx:      big.NewInt(15),
		Gy:      big.NewInt(13),
		BitSize: 18,
		Name:    "p1707",
	}
	log.Println(tiny_ec.IsOnCurveGeneric(big.NewInt(2), big.NewInt(10)))

	pub_k_X, pub_k_Y := new(big.Int), new(big.Int)
	for i := 0; i < 24; i++ {
		pub_k_X, pub_k_Y = tiny_ec.AddPointsGeneric(tiny_ec.Gx, tiny_ec.Gy, pub_k_X, pub_k_Y)
		log.Printf("Point %d, (%d, %d) \n", i, pub_k_X.Uint64(), pub_k_Y.Uint64())
	}

	secp256 := CurveParams{
		P:       bigFromHex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"),
		N:       bigFromHex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"),
		A:       big.NewInt(0),
		B:       big.NewInt(7),
		Gx:      bigFromHex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
		Gy:      bigFromHex("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"),
		BitSize: 256,
		Name:    "secp256k1",
	}
	log.Println(secp256.IsOnCurveGeneric(secp256.Gx, secp256.Gy))

	pub_k_X, pub_k_Y = secp256.AddPointsGeneric(secp256.Gx, secp256.Gy, secp256.Gx, secp256.Gy)
	pub_k_X, pub_k_Y = secp256.AddPointsGeneric(secp256.Gx, secp256.Gy, pub_k_X, pub_k_Y)
	log.Printf("Point %d, (%s, %s) \n", 2, fmt.Sprintf("%x", pub_k_X), fmt.Sprintf("%x", pub_k_Y))

	// priv, _, _, _ := GenerateKey(secp256, rand.Reader)
	// log.Println("Priv key", hex.EncodeToString(priv))

}

func (curve *CurveParams) ModInverseGeneric(k, p *big.Int) *big.Int {
	// Returns the inverse of k modulo p.
	// This function returns the only integer x such that (x * k) % p == 1.
	// k must be non-zero and p must be a prime.
	if k.Cmp(big.NewInt(0)) == 0 {
		log.Panic("division by zero")
		return nil
	}

	if k.Cmp(big.NewInt(0)) == -1 {
		return p.Sub(p, curve.ModInverseGeneric(k.Neg(k), p))
	}

	// Extended Euclidean algorithm.
	s, old_s := big.NewInt(0), big.NewInt(1)
	t, old_t := big.NewInt(1), big.NewInt(0)
	r, old_r := p, k
	quotient, m := new(big.Int), new(big.Int)

	for r.Cmp(big.NewInt(0)) != 0 {
		quotient.DivMod(old_r, r, m)                                         // r
		old_r, r = r, new(big.Int).Sub(old_r, new(big.Int).Mul(quotient, r)) //- quotient * r
		old_s, s = s, new(big.Int).Sub(old_s, new(big.Int).Mul(quotient, s)) //- quotient * s
		old_t, t = t, new(big.Int).Sub(old_t, new(big.Int).Mul(quotient, t)) //- quotient * t

	}

	gcd, x, _ := old_r, old_s, old_t

	if gcd.Cmp(big.NewInt(1)) != 0 {
		log.Panic("gcd !=1")
		return nil
	}

	k.Mul(k, x)
	k.Mod(k, p)

	if k.Cmp(big.NewInt(1)) != 0 {
		log.Panic("assert (k * x) % p == 1")
		return nil
	}
	return new(big.Int).Mod(x, p)
}

func (curve *CurveParams) PointNeg(x, y *big.Int) (*big.Int, *big.Int) {
	// """Returns -point."""
	if !curve.IsOnCurveGeneric(x, y) {
		log.Panic("Point is not on curve")
		return nil, nil
	}

	if x.Cmp(big.NewInt(0)) == 0 {
		return x, y
	}

	y.Mod(y, curve.P)
	y.Neg(y)

	return x, y
}

func (curve *CurveParams) AddPointsGeneric(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {

	if x1.Cmp(big.NewInt(0)) == 0 && y1.Cmp(big.NewInt(0)) == 0 {
		// 0 + point2 = point2
		return x2, y2
	}

	if x2.Cmp(big.NewInt(0)) == 0 && y2.Cmp(big.NewInt(0)) == 0 {
		// point1 + 0 = point1
		return x1, y1
	}

	if x1.Cmp(x2) == 0 && y1.Cmp(y2) != 0 {
		// point1 + (-point1) = 0
		return big.NewInt(0), big.NewInt(0)
	}

	lamda := new(big.Int)
	x3, y3 := new(big.Int), new(big.Int)

	if x1.Cmp(x2) == 0 {
		// This is the case point1 == point2.
		// (3 * x1 * x1 + curve.a) * inverse_mod(2 * y1, curve.p)
		lamda.Mul(x1, x1)
		lamda.Mul(lamda, big.NewInt(3))
		lamda.Add(lamda, curve.A)
		lamda.Mul(lamda, new(big.Int).ModInverse(new(big.Int).Mul(y1, big.NewInt(2)), curve.P))
	} else {
		// This is the case point1 != point2.
		// m = (y1 - y2) * inverse_mod(x1 - x2, curve.p)
		lamda.Mul(new(big.Int).Sub(y1, y2), new(big.Int).ModInverse(new(big.Int).Sub(x1, x2), curve.P))
	}
	x3.Mul(lamda, lamda)
	x3.Sub(x3, x1)
	x3.Sub(x3, x2)
	x3.Mod(x3, curve.P)

	y3.Add(y1, new(big.Int).Mul(lamda, new(big.Int).Sub(x3, x1)))
	y3.Neg(y3)
	y3.Mod(y3, curve.P)

	if !curve.IsOnCurveGeneric(x3, y3) {
		log.Panic("Point is not on curve")
		return nil, nil
	}

	return x3, y3
}

func (curve *CurveParams) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	return curve.ScalarMultGeneric_(curve.Gx, curve.Gy, k)
}

func (curve *CurveParams) ScalarMultGeneric_(Bx, By *big.Int, k []byte) (*big.Int, *big.Int) {

	if !curve.IsOnCurveGeneric(Bx, By) {
		log.Panic("Point is not on curve")
		return nil, nil
	}
	if Bx.Cmp(big.NewInt(0)) == 0 && Bx.Cmp(big.NewInt(0)) == 0 {
		log.Panic("Point is null")
		return nil, nil
	}

	result_x, result_y := new(big.Int), new(big.Int)
	addend_x, addend_y := Bx, By

	for _, byte := range k {
		for bitNum := 0; bitNum < 8; bitNum++ {
			addend_x, addend_y = curve.AddPointsGeneric(addend_x, addend_y, addend_x, addend_y)
			if byte&0x80 == 0x80 {
				result_x, result_y = curve.AddPointsGeneric(result_x, result_y, addend_x, addend_y)
			}
			byte <<= 1
		}
	}

	// if !curve.IsOnCurveGeneric (result_x, result_y) {
	// 	log.Panic("Point is not on curve")
	// 	return nil, nil
	// }

	return result_x, result_y
}

// CurveParams operates, internally, on Jacobian coordinates. For a given
// (x, y) position on the curve, the Jacobian coordinates are (x1, y1, z1)
// where x = x1/z1² and y = y1/z1³. The greatest speedups come when the whole
// calculation can be performed within the transform (as in ScalarMult and
// ScalarBaseMult). But even for Add and Double, it's faster to apply and
// reverse the transform than to operate in affine coordinates.

// polynomial returns x³ - 3x + b.
// PK polynomial returns x³ + ax + b.
func (curve *CurveParams) polynomialGeneric(x *big.Int) *big.Int {
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)

	aX := new(big.Int).Mul(curve.A, x)

	x3.Add(x3, aX)
	x3.Add(x3, curve.B)
	x3.Mod(x3, curve.P)

	return x3
}

func (curve *CurveParams) IsOnCurveGeneric(x, y *big.Int) bool {

	if x.Sign() < 0 || x.Cmp(curve.P) >= 0 ||
		y.Sign() < 0 || y.Cmp(curve.P) >= 0 {
			log.Fatal("Sign negative")
		return false
	}

	// y² = x³ - 3x + b
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, curve.P)

	return curve.polynomialGeneric(x).Cmp(y2) == 0
}

// GenerateKey returns a public/private key pair. The private key is
// generated using the given reader, which must return random data.
func GenerateKey(curve CurveParams, rand io.Reader) (priv []byte, x, y *big.Int, err error) {
	N := curve.N
	bitSize := N.BitLen()
	byteLen := (bitSize + 7) / 8
	priv = make([]byte, byteLen)

	for x == nil {
		_, err = io.ReadFull(rand, priv)
		if err != nil {
			return
		}
		// We have to mask off any excess bits in the case that the size of the
		// underlying field is not a whole number of bytes.
		priv[0] &= mask[bitSize%8]
		// This is because, in tests, rand will return all zeros and we don't
		// want to get the point at infinity and loop forever.
		priv[1] ^= 0x42

		// If the scalar is out of range, sample another random number.
		if new(big.Int).SetBytes(priv).Cmp(N) >= 0 {
			continue
		}

		x, y = curve.ScalarBaseMult(priv)
	}
	return
}

var mask = []byte{0xff, 0x1, 0x3, 0x7, 0xf, 0x1f, 0x3f, 0x7f}

func bigFromDecimal(s string) *big.Int {
	b, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("invalid encoding")
	}
	return b
}

func bigFromHex(s string) *big.Int {
	b, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("invalid encoding")
	}
	return b
}
