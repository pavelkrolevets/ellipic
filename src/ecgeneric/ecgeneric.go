package ecgeneric

import (
	"crypto"
	"io"
	"log"
	"math/big"
)

// PrivateKey represents an ECDSA private key.
type PrivateKey struct {
	PublicKey
	D *big.Int
}

// PublicKey represents an ECDSA public key.
type PublicKey struct {
	Curve
	X, Y *big.Int
}

// A Curve represents a short-form Weierstrass curve.
type Curve interface {
	// Params returns the parameters for the curve.
	Params() *CurveParams
	// IsOnCurve reports whether the given (x,y) lies on the curve.
	IsOnCurveGeneric(x, y *big.Int) bool
	// Add returns the sum of (x1,y1) and (x2,y2)
	AddPointsGeneric(x1, y1, x2, y2 *big.Int) (x, y *big.Int)
	// Double returns 2*(x,y)
	DoublePointsGeneric(x1, y1 *big.Int) (x, y *big.Int)
	// ScalarMult returns k*(Bx,By) where k is a number in big-endian form.
	ScalarMultGeneric(x1, y1, k *big.Int) (x, y *big.Int)
	// ScalarBaseMult returns k*G, where G is the base point of the group
	// and k is an integer in big-endian form.
	ScalarBaseMult(k *big.Int) (x, y *big.Int)
	ScalarBaseMultJ(k []byte) (x, y *big.Int)
	ScalarMultJ(Bx, By *big.Int, k []byte) (*big.Int, *big.Int)
	// Add returns the sum of (x1,y1) and (x2,y2)
	AddJ(x1, y1, x2, y2 *big.Int) (x, y *big.Int)
	// Double returns 2*(x,y)
	DoubleJ(x1, y1 *big.Int) (x, y *big.Int)
}

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

func (curve *CurveParams) Params() *CurveParams {
	return curve
}

func (curve *CurveParams) ScalarBaseMult(k *big.Int) (*big.Int, *big.Int) {
	return curve.ScalarMultGeneric(curve.Gx, curve.Gy, k)
}

func (curve *CurveParams) ScalarMultGeneric(Bx, By, k *big.Int) (*big.Int, *big.Int) {
	
	if !curve.IsOnCurveGeneric(Bx, By) {
		log.Panic("Point is not on curve")
		return nil, nil
	}
	
	if k.Cmp(big.NewInt(0)) == -1 {
		// k * point = -k * (-point)
		Bx, By = curve.PointNeg(Bx, By)
		return curve.ScalarMultGeneric(Bx, By, k.Neg(k))
	}

	if new(big.Int).Mod(k, curve.N).Cmp(big.NewInt(0)) == 0 {
		return big.NewInt(0), big.NewInt(0)
	}

	if Bx.Cmp(big.NewInt(0)) == 0 && Bx.Cmp(big.NewInt(0)) == 0 {
		// k * (0,0) = (0,0)
		return big.NewInt(0), big.NewInt(0)
	}


	xRes, yRes := new(big.Int), new(big.Int)
	xAddend, yAddend := Bx, By
	n := new(big.Int).Set(k)
	
	for n.Cmp(big.NewInt(0)) != 0 {
		if n.Bit(0) != 0 {
			// Add
			xRes, yRes = curve.AddPointsGeneric(xRes, yRes, xAddend, yAddend)
		}
		// Double
		xAddend, yAddend = curve.DoublePointsGeneric(xAddend, yAddend)
		n.Rsh(n, 1)
	}

	if !curve.IsOnCurveGeneric (xRes, yRes) {
		log.Panic("Point is not on curve")
		return nil, nil
	}

	return xRes, yRes
}


func (curve *CurveParams) AddPointsGeneric(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	
	if !curve.IsOnCurveGeneric(x1, y1) {
		log.Panic("Point is not on curve")
		return nil, nil
	}

	if !curve.IsOnCurveGeneric(x2, y2) {
		log.Panic("Point is not on curve")
		return nil, nil
	}

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

	// m = (y1 - y2) * inverse_mod(x1 - x2, curve.p)
	lamda.Mul(new(big.Int).Sub(y1, y2), new(big.Int).ModInverse(new(big.Int).Sub(x1, x2), curve.P))
	
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

func (curve *CurveParams) DoublePointsGeneric(x1, y1 *big.Int) (*big.Int, *big.Int) {

	if !curve.IsOnCurveGeneric(x1, y1) {
		log.Panic("Point is not on curve")
		return nil, nil
	}

	if x1.Cmp(big.NewInt(0)) == 0 && y1.Cmp(big.NewInt(0)) == 0 {
		// 0 * point2 = 0
		return big.NewInt(0), big.NewInt(0)
	}

	lamda := new(big.Int)
	x3, y3 := new(big.Int), new(big.Int)

	// (3 * x1 * x1 + curve.a) * inverse_mod(2 * y1, curve.p)
	lamda.Mul(x1, x1)
	lamda.Mul(lamda, big.NewInt(3))
	lamda.Add(lamda, curve.A)
	lamda.Mul(lamda, new(big.Int).ModInverse(new(big.Int).Mul(y1, big.NewInt(2)), curve.P))

	x3.Mul(lamda, lamda)
	x3.Sub(x3, x1)
	x3.Sub(x3, x1)
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

// polynomial returns x³ + ax + b.
func (curve *CurveParams) PolynomialGeneric(x *big.Int) *big.Int {
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

	if x.Cmp(big.NewInt(0)) == 0 && x.Cmp(big.NewInt(0)) == 0 {
		// Point at inf
		return true
	}

	// y² = x³ - 3x + b
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, curve.P)

	return curve.PolynomialGeneric(x).Cmp(y2) == 0
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

func BigFromHex(s string) *big.Int {
	return bigFromHex(s)
}

func BigFromDecimal(s string) *big.Int {
	return bigFromDecimal(s)
}

func (curve *CurveParams) polynomialGost(x *big.Int) *big.Int {
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)

	aX := new(big.Int).Mul(curve.A, x)

	x3.Add(x3, aX)
	x3.Add(x3, curve.B)
	x3.Mod(x3, curve.P)

	return x3
}

func (curve *CurveParams) IsOnCurve(x, y *big.Int) bool {

	if x.Sign() < 0 || x.Cmp(curve.P) >= 0 ||
		y.Sign() < 0 || y.Cmp(curve.P) >= 0 {
		return false
	}

	// y² = x³ + ax + b
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, curve.P)

	return curve.polynomialGost(x).Cmp(y2) == 0
}

// Public returns the public key corresponding to priv.
func (priv *PrivateKey) Public() crypto.PublicKey {
	return &priv.PublicKey
}

// Equal reports whether priv and x have the same value.
//
// See PublicKey.Equal for details on how Curve is compared.
func (priv *PrivateKey) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(*PrivateKey)
	if !ok {
		return false
	}
	return priv.PublicKey.Equal(&xx.PublicKey) && priv.D.Cmp(xx.D) == 0
}

func (pub *PublicKey) Equal(x crypto.PublicKey) bool {
	xx, ok := x.(*PublicKey)
	if !ok {
		return false
	}
	return pub.X.Cmp(xx.X) == 0 && pub.Y.Cmp(xx.Y) == 0 &&
		// Standard library Curve implementations are singletons, so this check
		// will work for those. Other Curves might be equivalent even if not
		// singletons, but there is no definitive way to check for that, and
		// better to err on the side of safety.
		pub.Curve == xx.Curve
}

// GenerateKey generates a public and private key pair.
func GenerateKey(c Curve, rand io.Reader) (*PrivateKey, error) {
	k, err := randFieldElement(c, rand)
	if err != nil {
		return nil, err
	}

	priv := new(PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMultJ(k.Bytes())
	return priv, nil
}


var one = new(big.Int).SetInt64(1)

// randFieldElement returns a random element of the order of the given
// curve using the procedure given in FIPS 186-4, Appendix B.5.1.
func randFieldElement(c Curve, rand io.Reader) (k *big.Int, err error) {
	params := c.Params()
	// Note that for P-521 this will actually be 63 bits more than the order, as
	// division rounds down, but the extra bit is inconsequential.
	b := make([]byte, params.BitSize/8+8) // TODO: use params.N.BitLen()
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}

	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}


// A invertible implements fast inverse in GF(N).
type invertible interface {
	// Inverse returns the inverse of k mod Params().N.
	Inverse(k *big.Int) *big.Int
}

// A combinedMult implements fast combined multiplication for verification.
type combinedMult interface {
	// CombinedMult returns [s1]G + [s2]P where G is the generator.
	CombinedMult(Px, Py *big.Int, s1, s2 []byte) (x, y *big.Int)
}

// CurveParams operates, internally, on Jacobian coordinates. For a given
// (x, y) position on the curve, the Jacobian coordinates are (x1, y1, z1)
// where x = x1/z1² and y = y1/z1³. The greatest speedups come when the whole
// calculation can be performed within the transform (as in ScalarMult and
// ScalarBaseMult). But even for Add and Double, it's faster to apply and
// reverse the transform than to operate in affine coordinates.

// polynomial returns x³ - 3x + b.
func (curve *CurveParams) polynomial(x *big.Int) *big.Int {
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)

	threeX := new(big.Int).Lsh(x, 1)
	threeX.Add(threeX, x)

	x3.Sub(x3, threeX)
	x3.Add(x3, curve.B)
	x3.Mod(x3, curve.P)

	return x3
}

func (curve *CurveParams) IsOnCurveJ(x, y *big.Int) bool {

	if x.Sign() < 0 || x.Cmp(curve.P) >= 0 ||
		y.Sign() < 0 || y.Cmp(curve.P) >= 0 {
		return false
	}

	// y² = x³ - 3x + b
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, curve.P)

	return curve.polynomial(x).Cmp(y2) == 0
}

// zForAffine returns a Jacobian Z value for the affine point (x, y). If x and
// y are zero, it assumes that they represent the point at infinity because (0,
// 0) is not on the any of the curves handled here.
func zForAffine(x, y *big.Int) *big.Int {
	z := new(big.Int)
	if x.Sign() != 0 || y.Sign() != 0 {
		z.SetInt64(1)
	}
	return z
}

// affineFromJacobian reverses the Jacobian transform. See the comment at the
// top of the file. If the point is ∞ it returns 0, 0.
func (curve *CurveParams) affineFromJacobian(x, y, z *big.Int) (xOut, yOut *big.Int) {
	if z.Sign() == 0 {
		return new(big.Int), new(big.Int)
	}

	zinv := new(big.Int).ModInverse(z, curve.P)
	zinvsq := new(big.Int).Mul(zinv, zinv)

	xOut = new(big.Int).Mul(x, zinvsq)
	xOut.Mod(xOut, curve.P)
	zinvsq.Mul(zinvsq, zinv)
	yOut = new(big.Int).Mul(y, zinvsq)
	yOut.Mod(yOut, curve.P)
	return
}

func (curve *CurveParams) AddJ(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {

	z1 := zForAffine(x1, y1)
	z2 := zForAffine(x2, y2)
	return curve.affineFromJacobian(curve.addJacobian(x1, y1, z1, x2, y2, z2))
}

// addJacobian takes two points in Jacobian coordinates, (x1, y1, z1) and
// (x2, y2, z2) and returns their sum, also in Jacobian form.
func (curve *CurveParams) addJacobian(x1, y1, z1, x2, y2, z2 *big.Int) (*big.Int, *big.Int, *big.Int) {
	// See https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-2007-bl
	x3, y3, z3 := new(big.Int), new(big.Int), new(big.Int)
	if z1.Sign() == 0 {
		x3.Set(x2)
		y3.Set(y2)
		z3.Set(z2)
		return x3, y3, z3
	}
	if z2.Sign() == 0 {
		x3.Set(x1)
		y3.Set(y1)
		z3.Set(z1)
		return x3, y3, z3
	}

	z1z1 := new(big.Int).Mul(z1, z1)
	z1z1.Mod(z1z1, curve.P)
	z2z2 := new(big.Int).Mul(z2, z2)
	z2z2.Mod(z2z2, curve.P)

	u1 := new(big.Int).Mul(x1, z2z2)
	u1.Mod(u1, curve.P)
	u2 := new(big.Int).Mul(x2, z1z1)
	u2.Mod(u2, curve.P)
	h := new(big.Int).Sub(u2, u1)
	xEqual := h.Sign() == 0
	if h.Sign() == -1 {
		h.Add(h, curve.P)
	}
	i := new(big.Int).Lsh(h, 1)
	i.Mul(i, i)
	j := new(big.Int).Mul(h, i)

	s1 := new(big.Int).Mul(y1, z2)
	s1.Mul(s1, z2z2)
	s1.Mod(s1, curve.P)
	s2 := new(big.Int).Mul(y2, z1)
	s2.Mul(s2, z1z1)
	s2.Mod(s2, curve.P)
	r := new(big.Int).Sub(s2, s1)
	if r.Sign() == -1 {
		r.Add(r, curve.P)
	}
	yEqual := r.Sign() == 0
	if xEqual && yEqual {
		return curve.doubleJacobian(x1, y1, z1)
	}
	r.Lsh(r, 1)
	v := new(big.Int).Mul(u1, i)

	x3.Set(r)
	x3.Mul(x3, x3)
	x3.Sub(x3, j)
	x3.Sub(x3, v)
	x3.Sub(x3, v)
	x3.Mod(x3, curve.P)

	y3.Set(r)
	v.Sub(v, x3)
	y3.Mul(y3, v)
	s1.Mul(s1, j)
	s1.Lsh(s1, 1)
	y3.Sub(y3, s1)
	y3.Mod(y3, curve.P)

	z3.Add(z1, z2)
	z3.Mul(z3, z3)
	z3.Sub(z3, z1z1)
	z3.Sub(z3, z2z2)
	z3.Mul(z3, h)
	z3.Mod(z3, curve.P)

	return x3, y3, z3
}

func (curve *CurveParams) DoubleJ(x1, y1 *big.Int) (*big.Int, *big.Int) {
	z1 := zForAffine(x1, y1)
	return curve.affineFromJacobian(curve.doubleJacobian(x1, y1, z1))
}

// doubleJacobian takes a point in Jacobian coordinates, (x, y, z), and
// returns its double, also in Jacobian form.
func (curve *CurveParams) doubleJacobian(x, y, z *big.Int) (*big.Int, *big.Int, *big.Int) {
	// See https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b
	delta := new(big.Int).Mul(z, z)
	delta.Mod(delta, curve.P)
	gamma := new(big.Int).Mul(y, y)
	gamma.Mod(gamma, curve.P)
	alpha := new(big.Int).Sub(x, delta)
	if alpha.Sign() == -1 {
		alpha.Add(alpha, curve.P)
	}
	alpha2 := new(big.Int).Add(x, delta)
	alpha.Mul(alpha, alpha2)
	alpha2.Set(alpha)
	alpha.Lsh(alpha, 1)
	alpha.Add(alpha, alpha2)

	beta := alpha2.Mul(x, gamma)

	x3 := new(big.Int).Mul(alpha, alpha)
	beta8 := new(big.Int).Lsh(beta, 3)
	beta8.Mod(beta8, curve.P)
	x3.Sub(x3, beta8)
	if x3.Sign() == -1 {
		x3.Add(x3, curve.P)
	}
	x3.Mod(x3, curve.P)

	z3 := new(big.Int).Add(y, z)
	z3.Mul(z3, z3)
	z3.Sub(z3, gamma)
	if z3.Sign() == -1 {
		z3.Add(z3, curve.P)
	}
	z3.Sub(z3, delta)
	if z3.Sign() == -1 {
		z3.Add(z3, curve.P)
	}
	z3.Mod(z3, curve.P)

	beta.Lsh(beta, 2)
	beta.Sub(beta, x3)
	if beta.Sign() == -1 {
		beta.Add(beta, curve.P)
	}
	y3 := alpha.Mul(alpha, beta)

	gamma.Mul(gamma, gamma)
	gamma.Lsh(gamma, 3)
	gamma.Mod(gamma, curve.P)

	y3.Sub(y3, gamma)
	if y3.Sign() == -1 {
		y3.Add(y3, curve.P)
	}
	y3.Mod(y3, curve.P)

	return x3, y3, z3
}

func (curve *CurveParams) ScalarMultJ(Bx, By *big.Int, k []byte) (*big.Int, *big.Int) {
	Bz := new(big.Int).SetInt64(1)
	x, y, z := new(big.Int), new(big.Int), new(big.Int)

	for _, byte := range k {
		for bitNum := 0; bitNum < 8; bitNum++ {
			x, y, z = curve.doubleJacobian(x, y, z)
			if byte&0x80 == 0x80 {
				x, y, z = curve.addJacobian(Bx, By, Bz, x, y, z)
			}
			byte <<= 1
		}
	}

	return curve.affineFromJacobian(x, y, z)
}

func (curve *CurveParams) ScalarBaseMultJ(k []byte) (*big.Int, *big.Int) {
	return curve.ScalarMultJ(curve.Gx, curve.Gy, k)
}

// GenerateKey returns a public/private key pair. The private key is
// generated using the given reader, which must return random data.
func GenerateKeyPair(curve Curve, rand io.Reader) (priv []byte, x, y *big.Int, err error) {
	N := curve.Params().N
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

		x, y = curve.ScalarBaseMultJ(priv)
	}
	return
}

// Marshal converts a point on the curve into the uncompressed form specified in
// SEC 1, Version 2.0, Section 2.3.3. If the point is not on the curve (or is
// the conventional point at infinity), the behavior is undefined.
func Marshal(curve Curve, x, y *big.Int) []byte {
	byteLen := (curve.Params().BitSize + 7) / 8

	ret := make([]byte, 1+2*byteLen)
	ret[0] = 4 // uncompressed point

	x.FillBytes(ret[1 : 1+byteLen])
	y.FillBytes(ret[1+byteLen : 1+2*byteLen])

	return ret
}


// hashToInt converts a hash value to an integer. Per FIPS 186-4, Section 6.4,
// we use the left-most bits of the hash to match the bit-length of the order of
// the curve. This also performs Step 5 of SEC 1, Version 2.0, Section 4.1.3.
func hashToInt(hash []byte, c Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}


// polynomial returns x³ - 3x + b.
func PolynomialNIST(curve *CurveParams, x *big.Int) *big.Int {
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)

	threeX := new(big.Int).Lsh(x, 1)
	threeX.Add(threeX, x)

	x3.Sub(x3, threeX)
	x3.Add(x3, curve.B)
	x3.Mod(x3, curve.P)

	return x3
}