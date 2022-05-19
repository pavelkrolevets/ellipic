package gost

import (
	"crypto/sha256"
	"io"
	"log"
	"math/big"

	"github.com/pavelkrolevets/ecdsa/ecgeneric"
)

var	GostEx1 = ecgeneric.CurveParams{
	// GOST простое число, p>3
	P:      ecgeneric.BigFromHex("8000000000000000000000000000000000000000000000000000000000000431"),
	// GOST порядок подгруппы группы точек эллиптической кривой - q
	N:      ecgeneric.BigFromHex("8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3"),
	A:      big.NewInt(7),
	B:      ecgeneric.BigFromHex("5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E"),
	// GOST rоэффициенты точки эллиптической кривой
	Gx:     ecgeneric.BigFromHex("2"),
	Gy:     ecgeneric.BigFromHex("8E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8"),
	BitSize: 256,
	Name:   "GostEx1",
}

func Hash(m []byte) ([32]byte) {
	b := sha256.Sum256(m)
	return b
}

func Sign(private_key *big.Int, m []byte, curve *ecgeneric.CurveParams, rand io.Reader) (r *big.Int, s *big.Int, err error) {
	// hash := new(big.Int).SetBytes(m[:])
	// N := curve.N
	// bitSize := N.BitLen()
	// byteLen := (bitSize + 7) / 8
	// k := make([]byte, byteLen)
	x, y := new(big.Int), new(big.Int)
	r, s = new(big.Int), new(big.Int)

	for r.Cmp(big.NewInt(0))== 0 && s.Cmp(big.NewInt(0))== 0 {
		// e :=  new(big.Int).Mod(hash, curve.N)
		// if e.Cmp(big.NewInt(0)) == 0 {
		// 	e.Set(big.NewInt(1))
		// }
		// _, err := io.ReadFull(rand, k)
		// if err != nil {
		// 	return nil, nil, err
		// }
		// k := new(big.Int).SetBytes(k[:])
		// if k.Cmp(curve.N) == 1 {
		// 	continue
		// }
		e := ecgeneric.BigFromHex("2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5")
		k := ecgeneric.BigFromHex("77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3")
		x, y = curve.ScalarBaseMult(k)
		log.Println("С=kР", x, y)
		r.Set(x.Mod(x, curve.N))
		s.Add(new(big.Int).Mul(r, private_key), new(big.Int).Mul(k, e))
		s.Mod(s, curve.N)
	}
	return
}

func Verify(m []byte, r, s, pubX, pubY *big.Int, curve *ecgeneric.CurveParams) (bool, error) {
	// hash := new(big.Int).SetBytes(m[:])
	// e :=  new(big.Int).Mod(hash, curve.N)
	// if e.Cmp(big.NewInt(0)) == 0 {
	// 	e.Set(big.NewInt(1))
	// }
	e := ecgeneric.BigFromHex("2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5")
	var v, z1, z2 = new(big.Int), new(big.Int), new(big.Int)
	
	v.ModInverse(e, GostEx1.N)
	log.Println("V", v)
	z1.Mul(s, v)
	z1.Mod(z1, GostEx1.N)

	z2.Mul(r, v)
	z2.Neg(z2)
	z2.Mod(z2, GostEx1.N)

	log.Println("z1", z1)
	log.Println("z2", z2)

	z1gX, z1gY := GostEx1.ScalarBaseMult(z1)
	u2mulPubX, u2mulPubY := GostEx1.ScalarMultGeneric(pubX, pubY, z2)
	x, y := GostEx1.AddPointsGeneric(z1gX, z1gY, u2mulPubX, u2mulPubY)
	log.Println("x,y", x, y)
	if new(big.Int).Mod(r, GostEx1.N).Cmp(new(big.Int).Mod(x, GostEx1.N)) == 0 {
		return true, nil
	} else {
		return false, nil
	}
}