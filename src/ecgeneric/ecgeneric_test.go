package ecgeneric_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/pavelkrolevets/gost-elliptic/src/ecgeneric"
	"github.com/pavelkrolevets/gost-elliptic/src/ecgeneric/gost"
	"github.com/pavelkrolevets/gost-elliptic/src/ecgeneric/nist"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

func Benchmark_gost_recover(b *testing.B) {
	priv := ecgeneric.BigFromHex("BA6048AADAE241BA40936D47756D7C93091A0E8514669700EE7508E508E102072E8123B2200A0563322DAD2827E2714A2636B7BFD18AADFC62967821FA18DD4")
	X, Y := gost.Gost341012512paramSetB.ScalarBaseMult(priv)
	m := []byte("Hello signature!")
	hash := sha3.New256()
	hash.Write(m)
	r, s, _ := gost.Sign(priv, hash.Sum(nil), &gost.Gost341012512paramSetB, rand.Reader)
	verify, _ := gost.Verify(hash.Sum(nil), r, s, X, Y, &gost.Gost341012512paramSetB)
	require.Equal(b, true, verify)
	msg := hash.Sum(nil)

	b.ResetTimer()
	b.Run("gost_recover", func(b *testing.B) {
		for i := 0; i < 1000; i++ {
			ecRecX, ecRecY := gost.Ecrecover(msg, r, s, X, Y, &gost.Gost341012512paramSetB)
			require.Equal(b, ecRecX, X)
			require.Equal(b, ecRecY, Y)
		}
	})
}

func Benchmark_gost_recover_j(b *testing.B) {
	priv := ecgeneric.BigFromHex("BA6048AADAE241BA40936D47756D7C93091A0E8514669700EE7508E508E102072E8123B2200A0563322DAD2827E2714A2636B7BFD18AADFC62967821FA18DD4")
	X, Y := gost.Gost341012512paramSetA.ScalarBaseMultJ(priv.Bytes())
	m := []byte("Hello signature!")
	hash := sha3.New256()
	hash.Write(m)
	r, s, _ := gost.SignJ(priv, hash.Sum(nil), &gost.Gost341012512paramSetA, rand.Reader)
	verify, _ := gost.VerifyJ(hash.Sum(nil), r, s, X, Y, &gost.Gost341012512paramSetA)
	require.Equal(b, true, verify)
	msg := hash.Sum(nil)

	b.ResetTimer()
	b.Run("gost_recover_Jacobian", func(b *testing.B) {
		for i := 0; i < 1000; i++ {
			ecRecX, ecRecY := gost.EcrecoverJ(msg, r, s, X, Y, &gost.Gost341012512paramSetA)
			require.Equal(b, ecRecX, X)
			require.Equal(b, ecRecY, Y)
		}
	})
}

func Benchmark_gost_sign(b *testing.B) {
	priv := ecgeneric.BigFromHex("BA6048AADAE241BA40936D47756D7C93091A0E8514669700EE7508E508E102072E8123B2200A0563322DAD2827E2714A2636B7BFD18AADFC62967821FA18DD4")
	X, Y := gost.Gost341012512paramSetA.ScalarBaseMult(priv)
	m := []byte("Hello signature!")
	hash := sha3.New256()
	hash.Write(m)
	msg := hash.Sum(nil)

	b.ResetTimer()
	b.Run("gost_sign", func(b *testing.B) {
		for i := 0; i < 100; i++ {
			r, s, _ := gost.Sign(priv, msg, &gost.Gost341012512paramSetA, rand.Reader)
			verify, _ := gost.Verify(msg, r, s, X, Y, &gost.Gost341012512paramSetA)
			require.Equal(b, true, verify)
		}
	})
}

func Benchmark_gost_sign_j(b *testing.B) {
	priv := ecgeneric.BigFromHex("BA6048AADAE241BA40936D47756D7C93091A0E8514669700EE7508E508E102072E8123B2200A0563322DAD2827E2714A2636B7BFD18AADFC62967821FA18DD4")
	X, Y := gost.Gost341012512paramSetA.ScalarBaseMultJ(priv.Bytes())
	m := []byte("Hello signature!")
	hash := sha3.New256()
	hash.Write(m)
	msg := hash.Sum(nil)

	b.ResetTimer()
	b.Run("gost_sign", func(b *testing.B) {
		for i := 0; i < 100; i++ {
			r, s, _ := gost.SignJ(priv, msg, &gost.Gost341012512paramSetA, rand.Reader)
			verify, _ := gost.VerifyJ(msg, r, s, X, Y, &gost.Gost341012512paramSetA)
			require.Equal(b, true, verify)
		}
	})
}

func Benchmark_secp256k1_sign(b *testing.B) {
	m := []byte("Hello signature!")
	hash := sha3.New256()
	hash.Write(m)
	msg := hash.Sum(nil)
	priv_ := ecgeneric.BigFromHex("52edb68fe48aff9b5c071f076285c53ac5b1a3501139bb2cb2922b7f3923d23e")

	b.ResetTimer()
	b.Run("secp256k1_sign", func(b *testing.B) {
		for i := 0; i < 1000; i++ {
			_, _, _ = nist.Sign(priv_, msg, &nist.Secp256k1, rand.Reader)
			
		}
	})
	
}
func Benchmark_nist_sign(b *testing.B) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	msg := "hello, world"
	hash := sha256.Sum256([]byte(msg))

	b.ResetTimer()
	b.Run("nist_sign", func(b *testing.B) {
		for i := 0; i < 10000; i++ {
			sig, _ := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
			valid := ecdsa.VerifyASN1(&privateKey.PublicKey, hash[:], sig)
			require.Equal(b, true, valid)
		}
	})
}