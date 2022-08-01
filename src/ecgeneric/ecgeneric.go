package ecgeneric

import (
	"log"
	"math/big"
)

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