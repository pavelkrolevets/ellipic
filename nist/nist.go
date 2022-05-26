package nist

import (
	"crypto/sha256"
	"io"
	"log"
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
	// N := curve.N
	// bitSize := N.BitLen()
	// byteLen := (bitSize + 7) / 8
	// k := make([]byte, byteLen)
	x := new(big.Int)
	r, s = new(big.Int), new(big.Int)

	for r.Cmp(big.NewInt(0))== 0 && s.Cmp(big.NewInt(0))== 0 {
		// _, err := io.ReadFull(rand, k)
		// if err != nil {
		// 	return nil, nil, err
		// }
		k := ecgeneric.BigFromHex("3885464172bf896aa10d45494a84f9232907e94020a293eb96be83ff476fc5b2")
		// if new(big.Int).SetBytes(k[:]).Cmp(curve.N) == 1 {
		// 	continue
		// }
		if k.Cmp(curve.N) > 0 {
			log.Fatal("Random is greater then oreder")
			continue
		}
		kModInv := new(big.Int).ModInverse(k, curve.N)
		x, _= curve.ScalarBaseMult(k)
		r.Set(x.Mod(x, curve.N))
		s.Mul(r, private_key)
		s.Add(hash, s)
		s.Mul(s, kModInv)
		s.Mod(s, curve.N)
	}
	return
}

func Verify(m []byte, r, s, pubX, pubY *big.Int) (bool, error) {
	z := new(big.Int).SetBytes(m[:]) 
	var w, u1, u2 = new(big.Int), new(big.Int), new(big.Int)
	
	w.ModInverse(s, Secp256k1.N)
	u1.Mul(z, w)
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

func Ecrecover(m []byte, r, s, pubX, pubY *big.Int) (*big.Int, *big.Int) {
	z := new(big.Int).SetBytes(m[:])
	var Rx,Ry, w, u1, u2 = new(big.Int), new(big.Int), new(big.Int), new(big.Int), new(big.Int)
	if r.Cmp(new(big.Int).Sub(Secp256k1.P, Secp256k1.N)) < 0 {
		log.Println("Two points")
	}
	x3 := new(big.Int).Mul(r, r)
	x3.Mul(x3, r)

	aX := new(big.Int).Mul(Secp256k1.A, r)

	x3.Add(x3, aX)
	x3.Add(x3, Secp256k1.B)
	x3.Mod(x3, Secp256k1.P)
	
	y0 := new(big.Int).ModSqrt(x3, Secp256k1.P)
	if y0.Cmp(big.NewInt(0)) == 0 {
		log.Fatal("No Y for X at the curve")
	}

	if (!Secp256k1.IsOnCurveGeneric(r, y0)){
		log.Fatal("r, y0 not on curve")
	}
	y1 := new(big.Int).Sub(Secp256k1.P, y0)
	if (!Secp256k1.IsOnCurveGeneric(r, y1)){
		log.Fatal("r, y1 not on curve")
	}
	// log.Println("y0 \n", y0)
	// log.Println("new(big.Int).Sub(Secp256k1.P, y0) \n", new(big.Int).Sub(Secp256k1.P, y0))
	
	// for Ry := y0; Ry.Cmp(new(big.Int).Sub(Secp256k1.P, y0)) < 0; Ry.Add(Ry, big.NewInt(1)) {

		
		// if y0.Bit(0) == 0 {
		// 	Ry.Set(y0)
		// 	Rx.Set(r)
		// } else {
		// 	Ry.Set(new(big.Int).Sub(Secp256k1.P, y0))
		// 	Rx.Set(r)
		// }
	
	Rx.Set(r)
	Ry.Set(y0)

	log.Printf("Points Rx, Ry, Ry1 (%s,%s,%s) \n", Rx, Ry, y1)
	if !Secp256k1.IsOnCurveGeneric(Rx, Ry) {
		log.Fatal("Rx, Ry not on curve")
	}
	
	w.ModInverse(r, Secp256k1.N)

	u1.Mul(z, w)
	u1.Neg(u1)
	u1.Mod(u1, Secp256k1.N)

	u2.Mul(s, w)
	u2.Mod(u2, Secp256k1.N)

	log.Printf("u1, u2 (%s, %s) \n", u1, u2)

	u1Gx, u1Gy := Secp256k1.ScalarBaseMult(u1)
	u2Rx, u2Ry := Secp256k1.ScalarMultGeneric(Rx, Ry, u2)

	Qx, Qy := Secp256k1.AddPointsGeneric(u1Gx, u1Gy, u2Rx, u2Ry)
	log.Printf("Qx, Qy (%s, %s) \n", Qx, Qy)
	if Qx.Cmp(pubX) == 0 && Qy.Cmp(pubY) == 0 {
			return Qx, Qy
		} 
			
	u2Rx_, u2Ry_ := Secp256k1.ScalarMultGeneric(Rx, y1, u2)

	Qx, Qy = Secp256k1.AddPointsGeneric(u1Gx, u1Gy, u2Rx_, u2Ry_)
	log.Printf("Qx, Qy (%s, %s) \n", Qx, Qy)
	if Qx.Cmp(pubX) == 0 && Qy.Cmp(pubY) == 0 {
			return Qx, Qy
		} else {
			return nil, nil
		}
		
}