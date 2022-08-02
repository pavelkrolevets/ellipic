package nist

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"log"
	"math/big"
)

func EcrecoverSTD(pub *ecdsa.PublicKey, c elliptic.Curve, hash []byte, r, s *big.Int) (*big.Int, *big.Int) {
	z := hashToInt(hash, c)
	var w, u1, u2 = new(big.Int), new(big.Int), new(big.Int)

	x3 := new(big.Int).Mul(r, r)
	x3.Mul(x3, r)

	threeX := new(big.Int).Lsh(r, 1)
	threeX.Add(threeX, r)

	x3.Sub(x3, threeX)
	x3.Add(x3, c.Params().B)
	x3.Mod(x3, c.Params().P)
	
	y0 := new(big.Int).ModSqrt(x3, c.Params().P)

	if y0.Cmp(big.NewInt(0)) == 0 {
		log.Fatal("No Y for X at the curve")
	}

	y1 := new(big.Int).Sub(c.Params().P, y0)
	if y1.Cmp(big.NewInt(0)) == 0 {
		log.Fatal("No Y for X at the curve")
	}
	w.ModInverse(r, c.Params().N)

	u1.Mul(z, w)
	u1.Neg(u1)
	u1.Mod(u1, c.Params().N)

	u2.Mul(s, w)
	u2.Mod(u2, c.Params().N)

	u1Gx, u1Gy := c.ScalarBaseMult(u1.Bytes())
	u2Rx, u2Ry := c.ScalarMult(r, y0, u2.Bytes())

	Qx, Qy := c.Add(u1Gx, u1Gy, u2Rx, u2Ry)
	if Qx.Cmp(pub.X) == 0 && Qy.Cmp(pub.Y) == 0 {
			return Qx, Qy
		} 
	u2Rx_, u2Ry_ := c.ScalarMult(r, y1, u2.Bytes())
	Qx, Qy = c.Add(u1Gx, u1Gy, u2Rx_, u2Ry_)
	if Qx.Cmp(pub.X) == 0 && Qy.Cmp(pub.Y) == 0 {
			return Qx, Qy
		} else {
			return nil, nil
		}
		
}

// hashToInt converts a hash value to an integer. Per FIPS 186-4, Section 6.4,
// we use the left-most bits of the hash to match the bit-length of the order of
// the curve. This also performs Step 5 of SEC 1, Version 2.0, Section 4.1.3.
func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
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