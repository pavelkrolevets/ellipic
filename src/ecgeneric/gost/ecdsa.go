package gost

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"io"
	"log"
	"math/big"

	"github.com/pavelkrolevets/gost-elliptic/src/ecgeneric"
	"github.com/pavelkrolevets/gost-elliptic/src/ecgeneric/randutil"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)
const (
	aesIV = "IV for ECDSA CTR"
)

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

// gost - 3410 - 2018 - 256
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
// gost - 3410 - 2018 - 256
var	GostEx2 = ecgeneric.CurveParams{
	// GOST простое число, p>3
	P:      ecgeneric.BigFromHex("4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15DF1D852741AF4704A0458047E80E4546D35B8336FAC224DD81664BBF528BE6373"),
	// GOST порядок подгруппы группы точек эллиптической кривой - q
	N:      ecgeneric.BigFromHex("4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15DA82F2D7ECB1DBAC719905C5EECC423F1D86E25EDBE23C595D644AAF187E6E6DF"),
	A:      ecgeneric.BigFromHex("7"),
	B:      ecgeneric.BigFromHex("1CFF0806A31116DA29D8CFA54E57EB748BC5F377E49400FDD788B649ECA1AC4361834013B2AD7322480A89CA58E0CF74BC9E540C2ADD6897FAD0A3084F302ADC"),
	// GOST rоэффициенты точки эллиптической кривой
	Gx:     ecgeneric.BigFromHex("24D19CC64572EE30F396BF6EBBFD7A6C5213B3B3D7057CC825F91093A68CD762FD60611262CD838DC6B60AA7EEE804E28BC849977FAC33B4B530F1B120248A9A"),
	Gy:     ecgeneric.BigFromHex("2BB312A43BD2CE6E0D020613C857ACDDCFBF061E91E5F2C3F32447C259F39B2C83AB156D77F1496BF7EB3351E1EE4E43DC1A18B91B24640B6DBB92CB1ADD371E"),
	BitSize: 256,
	Name:   "GostEx2",
}

// gost - 3410 - 12 - 512- paramSetA
var	Gost341012512paramSetA = ecgeneric.CurveParams{
	P:      ecgeneric.BigFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7"),
	N:      ecgeneric.BigFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275"),
	A:      ecgeneric.BigFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4"),
	B:      ecgeneric.BigFromHex("E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760"),
	Gx:     ecgeneric.BigFromHex("3"),
	Gy:     ecgeneric.BigFromHex("7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4"),
	BitSize: 512,
	Name:   "Gost341012512paramSetA",
}

// gost - 3410 - 12 - 512- paramSetB
var	Gost341012512paramSetB  = ecgeneric.CurveParams{
	P:      ecgeneric.BigFromHex("8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006F"),
	N:      ecgeneric.BigFromHex("800000000000000000000000000000000000000000000000000000000000000149A1EC142565A545ACFDB77BD9D40CFA8B996712101BEA0EC6346C54374F25BD"),
	A:      ecgeneric.BigFromHex("8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006C"),
	B:      ecgeneric.BigFromHex("687D1B459DC841457E3E06CF6F5E2517B97C7D614AF138BCBF85DC806C4B289F3E965D2DB1416D217F8B276FAD1AB69C50F78BEE1FA3106EFB8CCBC7C5140116"),
	Gx:     ecgeneric.BigFromHex("2"),
	Gy:     ecgeneric.BigFromHex("1A8F7EDA389B094C2C071E3647A8940F3C123B697578C213BE6DD9E6C8EC7335DCB228FD1EDF4A39152CBCAAF8C0398828041055F94CEEEC7E21340780FE41BD"),
	BitSize: 512,
	Name:   "Gost341012512paramSetB",
}

// gost - 3410 - 12 - 2001- paramSetA
var	Gost34102001paramSetA  = ecgeneric.CurveParams{
	P:      ecgeneric.BigFromHex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97"),
	N:      ecgeneric.BigFromHex("ffffffffffffffffffffffffffffffff6c611070995ad10045841b09b761b893"),
	A:      ecgeneric.BigFromHex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd94"),
	B:      ecgeneric.BigFromHex("00000000000000000000000000000000000000000000000000000000000000a6"),
	Gx:     ecgeneric.BigFromHex("0000000000000000000000000000000000000000000000000000000000000001"),
	Gy:     ecgeneric.BigFromHex("8d91e471e0989cda27df505a453f2b7635294f2ddf23e3b122acc99c9e9f1e14"),
	BitSize: 256,
	Name:   "id-gostR3410-2001-CryptoPro-A-ParamSet",
}

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
	r, s = new(big.Int), new(big.Int)

	for r.Cmp(big.NewInt(0))== 0 && s.Cmp(big.NewInt(0))== 0 {
		e :=  new(big.Int).Mod(hash, curve.N)
		if e.Cmp(big.NewInt(0)) == 0 {
			e.Set(big.NewInt(1))
		}
		_, err := io.ReadFull(rand, k)
		if err != nil {
			return nil, nil, err
		}
		k := new(big.Int).SetBytes(k[:])
		if k.Cmp(curve.N) == 1 {
			continue
		}
		x, _ := curve.ScalarBaseMult(k)
		r.Set(x.Mod(x, curve.N))
		s.Add(new(big.Int).Mul(r, private_key), new(big.Int).Mul(k, e))
		s.Mod(s, curve.N)
	}
	return
}

func Verify(m []byte, r, s, pubX, pubY *big.Int, curve *ecgeneric.CurveParams) (bool, error) {
	hash := new(big.Int).SetBytes(m[:])
	e :=  new(big.Int).Mod(hash, curve.N)
	if e.Cmp(big.NewInt(0)) == 0 {
		e.Set(big.NewInt(1))
	}
	var v, z1, z2 = new(big.Int), new(big.Int), new(big.Int)
	
	v.ModInverse(e, curve.N)
	z1.Mul(s, v)
	z1.Mod(z1, curve.N)
	z2.Mul(r, v)
	z2.Neg(z2)
	z2.Mod(z2, curve.N)

	z1gX, z1gY := curve.ScalarBaseMult(z1)
	u2mulPubX, u2mulPubY := curve.ScalarMultGeneric(pubX, pubY, z2)
	x, _ := curve.AddPointsGeneric(z1gX, z1gY, u2mulPubX, u2mulPubY)
	if new(big.Int).Mod(r, curve.N).Cmp(new(big.Int).Mod(x, curve.N)) == 0 {
		return true, nil
	} else {
		return false, nil
	}
}

func Ecrecover(m []byte, r, s, pubX, pubY *big.Int, curve *ecgeneric.CurveParams) (*big.Int, *big.Int) {
	z := new(big.Int).SetBytes(m[:])
	var Rx,Ry, w, u1, u2 = new(big.Int), new(big.Int), new(big.Int), new(big.Int), new(big.Int)
	x3 := new(big.Int).Mul(r, r)
	x3.Mul(x3, r)
	aX := new(big.Int).Mul(curve.A, r)
	x3.Add(x3, aX)
	x3.Add(x3, curve.B)
	x3.Mod(x3, curve.P)
	
	y0 := new(big.Int).ModSqrt(x3, curve.P)
	if y0.Cmp(big.NewInt(0)) == 0 {
		log.Fatal("No Y for X at the curve")
	}

	if (!curve.IsOnCurveGeneric(r, y0)){
		log.Fatal("r, y0 not on curve")
	}
	y1 := new(big.Int).Sub(curve.P, y0)
	if (!curve.IsOnCurveGeneric(r, y1)){
		log.Fatal("r, y1 not on curve")
	}
	
	Rx.Set(r)
	Ry.Set(y0)

	if !curve.IsOnCurveGeneric(r, y0) {
		log.Fatal("r, y0 not on curve")
	}
	if !curve.IsOnCurveGeneric(r, y1) {
		log.Fatal("r, y1 not on curve")
	}
	
	w.ModInverse(r, curve.N)
	
	u1.Mul(s, w)
	u1.Mod(u1, curve.N)

	u2.Mul(z, w)
	u2.Neg(u2)
	u2.Mod(u2, curve.N)

	u1Gx, u1Gy := curve.ScalarBaseMult(u1)
	u2Rx, u2Ry := curve.ScalarMultGeneric(Rx, Ry, u2)

	Qx, Qy := curve.AddPointsGeneric(u1Gx, u1Gy, u2Rx, u2Ry)
	if Qx.Cmp(pubX) == 0 && Qy.Cmp(pubY) == 0 {
			return Qx, Qy
		} 
			
	u2Rx_, u2Ry_ := curve.ScalarMultGeneric(Rx, y1, u2)
	Qx, Qy = curve.AddPointsGeneric(u1Gx, u1Gy, u2Rx_, u2Ry_)
	if Qx.Cmp(pubX) == 0 && Qy.Cmp(pubY) == 0 {
			return Qx, Qy
		} else {
			return nil, nil
		}		
}

func EcrecoverJ(m []byte, r, s, pubX, pubY *big.Int, curve *ecgeneric.CurveParams) (*big.Int, *big.Int) {
	z := hashToInt(m, curve)
	var Rx,Ry, w, u1, u2 = new(big.Int), new(big.Int), new(big.Int), new(big.Int), new(big.Int)
	x3 := new(big.Int).Mul(r, r)
	x3.Mul(x3, r)
	aX := new(big.Int).Mul(curve.A, r)
	x3.Add(x3, aX)
	x3.Add(x3, curve.B)
	x3.Mod(x3, curve.P)
	
	y0 := new(big.Int).ModSqrt(x3, curve.P)
	if y0.Cmp(big.NewInt(0)) == 0 {
		log.Fatal("No Y for X at the curve")
	}
	y1 := new(big.Int).Sub(curve.P, y0)
	
	Rx.Set(r)
	Ry.Set(y0)
	
	w.ModInverse(r, curve.N)
	
	u1.Mul(s, w)
	u1.Mod(u1, curve.N)

	u2.Mul(z, w)
	u2.Neg(u2)
	u2.Mod(u2, curve.N)

	u1Gx, u1Gy := curve.ScalarBaseMultJ(u1.Bytes())
	u2Rx, u2Ry := curve.ScalarMultJ(Rx, Ry, u2.Bytes())

	Qx, Qy := curve.AddJ(u1Gx, u1Gy, u2Rx, u2Ry)
	if Qx.Cmp(pubX) == 0 && Qy.Cmp(pubY) == 0 {
			return Qx, Qy
		} 
			
	u2Rx_, u2Ry_ := curve.ScalarMultJ(Rx, y1, u2.Bytes())
	Qx, Qy = curve.AddJ(u1Gx, u1Gy, u2Rx_, u2Ry_)
	if Qx.Cmp(pubX) == 0 && Qy.Cmp(pubY) == 0 {
			return Qx, Qy
		} else {
			return nil, nil
		}		
}

// returns the ASN.1 encoded signature.
func SignASN1(private_key *big.Int, hash []byte, curve *ecgeneric.CurveParams, rand io.Reader) ([]byte, error) {
	r, s, err := Sign(private_key, hash, curve, rand)
	if err != nil {
		return nil, err
	}

	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(r)
		b.AddASN1BigInt(s)
	})
	return b.Bytes()
}

var errZeroParam = errors.New("zero parameter")


func signSTD(priv *ecgeneric.PrivateKey, csprng *cipher.StreamReader, c ecgeneric.Curve, hash []byte) (r *big.Int, s *big.Int, err error) {
	// SEC 1, Version 2.0, Section 4.1.3
	N := c.Params().N
	if N.Sign() == 0 {
		return nil, nil, errZeroParam
	}
	var k, kInv *big.Int
	for {
		for {
			k, err = randFieldElement(c, *csprng)
			if err != nil {
				r = nil
				return
			}

			if in, ok := priv.Curve.(invertible); ok {
				kInv = in.Inverse(k)
			} else {
				kInv = fermatInverse(k, N) // N != 0
			}

			r, _ = priv.Curve.ScalarBaseMultJ(k.Bytes())
			r.Mod(r, N)
			if r.Sign() != 0 {
				break
			}
		}

		e := hashToInt(hash, c)
		s = new(big.Int).Mul(priv.D, r)
		s.Add(s, e)
		s.Mul(s, kInv)
		s.Mod(s, N) // N != 0
		if s.Sign() != 0 {
			break
		}
	}
	return
}

func verifySTD(pub *ecgeneric.PublicKey, c ecgeneric.Curve, hash []byte, r, s *big.Int) bool {
	// SEC 1, Version 2.0, Section 4.1.4
	e := hashToInt(hash, c)
	var w *big.Int
	N := c.Params().N
	if in, ok := c.(invertible); ok {
		w = in.Inverse(s)
	} else {
		w = new(big.Int).ModInverse(s, N)
	}

	u1 := e.Mul(e, w)
	u1.Mod(u1, N)
	u2 := w.Mul(r, w)
	u2.Mod(u2, N)

	// Check if implements S1*g + S2*p
	var x, y *big.Int
	if opt, ok := c.(combinedMult); ok {
		x, y = opt.CombinedMult(pub.X, pub.Y, u1.Bytes(), u2.Bytes())
	} else {
		x1, y1 := c.ScalarBaseMultJ(u1.Bytes())
		x2, y2 := c.ScalarMultJ(pub.X, pub.Y, u2.Bytes())
		x, y = c.AddJ(x1, y1, x2, y2)
	}

	if x.Sign() == 0 && y.Sign() == 0 {
		return false
	}
	x.Mod(x, N)
	return x.Cmp(r) == 0
}

// hashToInt converts a hash value to an integer. Per FIPS 186-4, Section 6.4,
// we use the left-most bits of the hash to match the bit-length of the order of
// the curve. This also performs Step 5 of SEC 1, Version 2.0, Section 4.1.3.
func hashToInt(hash []byte, c ecgeneric.Curve) *big.Int {
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

var one = new(big.Int).SetInt64(1)

// randFieldElement returns a random element of the order of the given
// curve using the procedure given in FIPS 186-4, Appendix B.5.1.
func randFieldElement(c ecgeneric.Curve, rand io.Reader) (k *big.Int, err error) {
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

func SignJ(private_key *big.Int, m []byte, curve *ecgeneric.CurveParams, rand io.Reader) (r *big.Int, s *big.Int, err error) {
	hash := hashToInt(m, curve)
	N := curve.N
	bitSize := N.BitLen()
	byteLen := (bitSize + 7) / 8
	k := make([]byte, byteLen)
	r, s = new(big.Int), new(big.Int)

	for r.Cmp(big.NewInt(0))== 0 && s.Cmp(big.NewInt(0))== 0 {
		e :=  new(big.Int).Mod(hash, curve.N)
		if e.Cmp(big.NewInt(0)) == 0 {
			e.Set(big.NewInt(1))
		}
		_, err := io.ReadFull(rand, k)
		if err != nil {
			return nil, nil, err
		}
		x, _ := curve.ScalarBaseMultJ(k)
		k := new(big.Int).SetBytes(k[:])
		if k.Cmp(curve.N) == 1 {
			continue
		}
		r.Set(x.Mod(x, curve.N))
		s.Add(new(big.Int).Mul(r, private_key), new(big.Int).Mul(k, e))
		s.Mod(s, curve.N)
	}
	return
}

func VerifyJ(m []byte, r, s, pubX, pubY *big.Int, curve *ecgeneric.CurveParams) (bool, error) {
	hash := hashToInt(m, curve)
	e :=  new(big.Int).Mod(hash, curve.N)
	if e.Cmp(big.NewInt(0)) == 0 {
		e.Set(big.NewInt(1))
	}
	var v, z1, z2 = new(big.Int), new(big.Int), new(big.Int)
	
	v.ModInverse(e, curve.N)
	z1.Mul(s, v)
	z1.Mod(z1, curve.N)
	z2.Mul(r, v)
	z2.Neg(z2)
	z2.Mod(z2, curve.N)

	z1gX, z1gY := curve.ScalarBaseMultJ(z1.Bytes())
	u2mulPubX, u2mulPubY := curve.ScalarMultJ(pubX, pubY, z2.Bytes())
	x, _ := curve.AddJ(z1gX, z1gY, u2mulPubX, u2mulPubY)
	if new(big.Int).Mod(r, curve.N).Cmp(new(big.Int).Mod(x, curve.N)) == 0 {
		return true, nil
	} else {
		return false, nil
	}
}

func fermatInverse(k, N *big.Int) *big.Int {
	two := big.NewInt(2)
	nMinus2 := new(big.Int).Sub(N, two)
	return new(big.Int).Exp(k, nMinus2, N)
}


func SignSTD(rand io.Reader, priv *ecgeneric.PrivateKey, hash []byte) (r, s *big.Int, err error) {
	randutil.MaybeReadByte(rand)

	// This implementation derives the nonce from an AES-CTR CSPRNG keyed by:
	//
	//    SHA2-512(priv.D || entropy || hash)[:32]
	//
	// The CSPRNG key is indifferentiable from a random oracle as shown in
	// [Coron], the AES-CTR stream is indifferentiable from a random oracle
	// under standard cryptographic assumptions (see [Larsson] for examples).
	//
	// [Coron]: https://cs.nyu.edu/~dodis/ps/merkle.pdf
	// [Larsson]: https://web.archive.org/web/20040719170906/https://www.nada.kth.se/kurser/kth/2D1441/semteo03/lecturenotes/assump.pdf

	// Get 256 bits of entropy from rand.
	entropy := make([]byte, 32)
	_, err = io.ReadFull(rand, entropy)
	if err != nil {
		return
	}

	// Initialize an SHA-512 hash context; digest...
	md := sha512.New()
	md.Write(priv.D.Bytes()) // the private key,
	md.Write(entropy)        // the entropy,
	md.Write(hash)           // and the input hash;
	key := md.Sum(nil)[:32]  // and compute ChopMD-256(SHA-512),
	// which is an indifferentiable MAC.

	// Create an AES-CTR instance to use as a CSPRNG.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	// Create a CSPRNG that xors a stream of zeros with
	// the output of the AES-CTR instance.
	csprng := cipher.StreamReader{
		R: zeroReader,
		S: cipher.NewCTR(block, []byte(aesIV)),
	}

	c := priv.PublicKey.Curve
	return signSTD(priv, &csprng, c, hash)
}

func VerifySTD(pub *ecgeneric.PublicKey, hash []byte, r, s *big.Int) bool {
	c := pub.Curve
	N := c.Params().N

	if r.Sign() <= 0 || s.Sign() <= 0 {
		return false
	}
	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return false
	}
	return verifySTD(pub, c, hash, r, s)
}

type zr struct {
	io.Reader
}

// Read replaces the contents of dst with zeros.
func (z *zr) Read(dst []byte) (n int, err error) {
	for i := range dst {
		dst[i] = 0
	}
	return len(dst), nil
}

var zeroReader = &zr{}

func EcrecoverSTD(pub *ecgeneric.PublicKey, c ecgeneric.Curve, hash []byte, r, s *big.Int) (*big.Int, *big.Int) {
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

	u1Gx, u1Gy := c.ScalarBaseMultJ(u1.Bytes())
	u2Rx, u2Ry := c.ScalarMultJ(r, y0, u2.Bytes())

	Qx, Qy := c.AddJ(u1Gx, u1Gy, u2Rx, u2Ry)
	if Qx.Cmp(pub.X) == 0 && Qy.Cmp(pub.Y) == 0 {
			return Qx, Qy
		} 
	u2Rx_, u2Ry_ := c.ScalarMultJ(r, y1, u2.Bytes())
	Qx, Qy = c.AddJ(u1Gx, u1Gy, u2Rx_, u2Ry_)
	if Qx.Cmp(pub.X) == 0 && Qy.Cmp(pub.Y) == 0 {
			return Qx, Qy
		} else {
			return nil, nil
		}
		
}